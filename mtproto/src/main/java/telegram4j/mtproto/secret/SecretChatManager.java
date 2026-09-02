/*
 * Copyright 2023 Telegram4J
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package telegram4j.mtproto.secret;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.Logger;
import reactor.util.Loggers;
import reactor.util.annotation.Nullable;
import telegram4j.mtproto.auth.AuthKey;
import telegram4j.mtproto.auth.DhParameters;
import telegram4j.mtproto.auth.DhPrimeChecker;
import telegram4j.mtproto.auth.DhPrimeCheckerCache;
import telegram4j.mtproto.service.ChatService;
import telegram4j.mtproto.store.SecretChatStore;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import telegram4j.tl.*;
import telegram4j.tl.request.messages.ImmutableSendEncrypted;
import telegram4j.tl.secret.*;
import telegram4j.tl.messages.BaseDhConfig;
import telegram4j.tl.messages.DhConfigNotModified;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;

import static telegram4j.mtproto.util.CryptoUtil.random;

/**
 * Establishes and tears down secret chats.
 *
 * <p> Nothing here decides when a chat should be opened; the caller does that, and this turns it
 * into the exchange the protocol requires and into state that survives a restart.
 *
 * @implNote The order of the writes matters more than it looks. Every state change is persisted
 * before the request that makes it visible to the peer, never after, so that a process which dies
 * mid-exchange leaves a chat we can still key rather than one the peer believes in and we cannot.
 */
public final class SecretChatManager {

    private static final Logger log = Loggers.getLogger(SecretChatManager.class);

    /** The highest layer of the end-to-end schema this implementation can speak. */
    public static final int LAYER = SecretTlInfo.LAYER;

    /** Length of the padding inside {@code decryptedMessageLayer}, as TDLib writes it. */
    private static final int RANDOM_BYTES = 31;

    private final ChatService service;
    private final SecretChatStore store;
    private final DhPrimeChecker primeChecker;
    private final boolean acceptLegacyMTProto;

    private volatile int dhVersion;
    @Nullable
    private volatile DhParameters parameters;

    /**
     * How many messages one chat may hold behind a gap.
     *
     * <p> Without a bound this grows as long as the peer keeps talking, and a peer whose first
     * message went missing can make it grow on purpose. A hundred matches how long a key is
     * allowed to live, so a chat cannot hold more than one key's worth of history. Worth turning
     * into a setting if a caller ever needs a different trade between memory and tolerance.
     */
    private static final int MAX_HELD_MESSAGES = 100;

    /** Messages held behind a gap, per chat, newest last. Not persisted: a restart refetches them. */
    private final Map<Integer, NavigableMap<Integer, DecryptedMessageLayer>> pending =
        new ConcurrentHashMap<>();

    /** How many resend requests one chat may send in {@link #RESEND_WINDOW} before it is muted. */
    private static final int MAX_RESENDS = 3;
    private static final Duration RESEND_WINDOW = Duration.ofSeconds(30);
    private static final Duration RESEND_COOLDOWN = Duration.ofMinutes(5);

    private final Map<Integer, ResendLimit> resendLimits = new ConcurrentHashMap<>();


    public SecretChatManager(ChatService service, SecretChatStore store) {
        this(service, store, DhPrimeCheckerCache.instance(), false);
    }

    /**
     * @param acceptLegacyMTProto Whether incoming MTProto 1.0 messages are read; see
     * {@link SecretChatCipher#SecretChatCipher(boolean)} for what that costs and why peers exist
     * which need it.
     */
    public SecretChatManager(ChatService service, SecretChatStore store,
                             DhPrimeChecker primeChecker, boolean acceptLegacyMTProto) {
        this.service = Objects.requireNonNull(service);
        this.store = Objects.requireNonNull(store);
        this.primeChecker = Objects.requireNonNull(primeChecker);
        this.acceptLegacyMTProto = acceptLegacyMTProto;
    }

    /**
     * Asks the given user to open a secret chat.
     *
     * <p> The chat is not usable when this completes: the peer must accept it first, which it may
     * do at any point or never. The returned state is {@link SecretChatState.Status#REQUESTED} and
     * becomes usable when {@link #onUpdate(EncryptedChat)} sees the acceptance.
     *
     * @param user The user to invite.
     * @return A {@link Mono} emitting the stored state of the pending chat.
     */
    public Mono<SecretChatState> requestSecretChat(InputUser user) {
        Objects.requireNonNull(user);

        return dhParameters().flatMap(dh -> {
            var secret = DhParameters.generateSecret();
            var gA = dh.computePublicKeyData(secret);

            return service.requestEncryption(user, random.nextInt(), gA)
                    .flatMap(chat -> {
                        if (!(chat instanceof EncryptedChatWaiting waiting)) {
                            return Mono.error(new SecretChatException(
                                    "Unexpected answer to requestEncryption: " + chat));
                        }

                        var state = SecretChatState.builder(waiting.id(), waiting.accessHash(),
                                        waiting.participantId(), true)
                                .status(SecretChatState.Status.REQUESTED)
                                .secret(secret)
                                .build();

                        log.debug("Requested secret chat {} with user {}", waiting.id(), waiting.participantId());
                        return store.updateSecretChat(state).thenReturn(state);
                    });
        });
    }

    /**
     * Applies an {@code updateEncryption} to the stored state, keying or discarding the chat.
     *
     * @param chat The {@link EncryptedChat} carried by the update.
     * @return A {@link Mono} emitting the new state, or empty for an update that changes nothing.
     */
    public Mono<SecretChatState> onUpdate(EncryptedChat chat) {
        Objects.requireNonNull(chat);

        return switch (chat.identifier()) {
            case EncryptedChatRequested.ID -> accept((EncryptedChatRequested) chat);
            case BaseEncryptedChat.ID -> complete((BaseEncryptedChat) chat);
            case EncryptedChatDiscarded.ID -> discarded((EncryptedChatDiscarded) chat);
            // waiting is our own request coming back, and empty carries nothing to apply
            case EncryptedChatWaiting.ID, EncryptedChatEmpty.ID -> Mono.empty();
            default -> Mono.error(new SecretChatException("Unexpected EncryptedChat: " + chat));
        };
    }

    /**
     * Tears down a secret chat and forgets its key.
     *
     * @param chatId The id of the chat.
     * @param deleteHistory Whether the peer should also drop the conversation.
     * @return A {@link Mono} completing when the chat is gone from the store.
     */
    public Mono<Void> discardSecretChat(int chatId, boolean deleteHistory) {
        return service.discardEncryption(deleteHistory, chatId)
                // the server may already consider it gone, which is the outcome we wanted anyway
                .onErrorResume(e -> {
                    log.debug("Failed to discard secret chat {}, forgetting it regardless", chatId, e);
                    return Mono.just(true);
                })
                .then(store.deleteSecretChat(chatId));
    }

    /**
     * Tells the peer that its messages up to the given date have been read.
     *
     * <p> Nothing in the chat state depends on this, so a failure is the caller's to ignore: the
     * peer simply keeps showing the messages as unread.
     *
     * @param chatId The id of the chat.
     * @param maxDate The {@code date} of the newest message that has been read.
     * @return A {@link Mono} completing when the server has taken the notice.
     */
    public Mono<Void> markHistoryWasRead(int chatId, int maxDate) {
        return withChat(chatId, state -> service.readEncryptedHistory(
                        ImmutableInputEncryptedChat.of(state.id(), state.accessHash()), maxDate)
                .then());
    }

    /** {@return Every known secret chat, including the ones awaiting acceptance} */
    public Flux<SecretChatState> getSecretChats() {
        return store.getSecretChats();
    }

    /**
     * Sends a text message to a secret chat.
     *
     * @param chatId The id of the chat, which must be {@link SecretChatState.Status#READY}.
     * @param text The message.
     * @return A {@link Mono} completing when the server has taken the message.
     */
    public Mono<Void> sendMessage(int chatId, String text) {
        Objects.requireNonNull(text);

        // also checked after sending, so a chat nobody answers still replaces its key
        return withChat(chatId, state -> send(state, BaseDecryptedMessage.builder()
                .randomId(random.nextLong())
                .ttl(state.ttl())
                .message(text)
                .build(), false)
                .flatMap(sent -> rekeyIfWorn(sent).thenReturn(sent)));
    }

    /**
     * Applies an {@code updateNewEncryptedMessage} to the chat it belongs to.
     *
     * <p> A message that fills a gap releases everything held behind it, so one update can emit
     * several, in the order the peer sent them.
     *
     * <p> TODO low priority: the same message can be handed here twice. Encrypted messages are
     * sequenced by {@code qts}, which {@code DefaultUpdatesManager} tracks but nothing advances
     * on our behalf, so the server repeats updates it considers unacknowledged. Nothing breaks,
     * since a repeat is recognised and dropped, but it costs a decryption and a write each time.
     * Fixing it belongs to update state management rather than here.
     *
     * @param message The {@link EncryptedMessage} carried by the update.
     * @return A {@link Flux} emitting what the peer sent, empty when the message was a service
     * action, a repeat of one already processed, or is being held until the messages before it
     * arrive.
     */
    public Flux<DecryptedMessage> onNewMessage(EncryptedMessage message) {
        Objects.requireNonNull(message);

        int chatId = message.chatId();
        return store.getSecretChat(chatId)
                .switchIfEmpty(Mono.error(() -> new SecretChatException("No secret chat with id " + chatId)))
                .flatMapMany(state -> Flux.defer(() -> decrypt(state, message)));
    }

    /**
     * Gives up on the messages a chat is waiting for and carries on with what came after them.
     *
     * <p> A gap normally clears itself: the missing messages arrive, or the peer resends them
     * when asked. Neither happens when the peer is TDLib, which asks for resends but answers
     * none, so a message lost on the way leaves the chat stuck for good. This is the way out,
     * and it is deliberately manual because it throws those messages away: their contents are
     * gone, and if one of them changed the layer or the key, that change is lost with it.
     *
     * @param chatId The id of the chat.
     * @return A {@link Flux} emitting the messages that were held behind the gap.
     */
    public Flux<DecryptedMessage> skipGap(int chatId) {
        return store.getSecretChat(chatId)
                .switchIfEmpty(Mono.error(() -> new SecretChatException("No secret chat with id " + chatId)))
                .flatMapMany(state -> {
                    var held = pending.get(chatId);
                    if (held == null || held.isEmpty()) {
                        log.debug("Secret chat {} is not waiting for anything", chatId);
                        return Flux.empty();
                    }

                    int resumeAt = held.firstKey();
                    log.warn("Giving up on messages {}..{} of secret chat {}",
                            state.seqNo().inSeqNo(), resumeAt - 1, chatId);

                    var resumed = state.toBuilder()
                            .seqNo(new SeqNoState(state.creator(), resumeAt,
                                    state.seqNo().outSeqNo(), state.seqNo().remoteInSeqNo()))
                            .build();
                    return store.updateSecretChat(resumed)
                            .thenMany(Flux.defer(() -> releaseHeldMessages(resumed)));
                });
    }

    /**
     * Asks the peer to send again what we are missing, unless this chat has been asking too often.
     *
     * <p> The bounds are in the peer's own numbering, since it is the one being asked. Peers
     * differ in whether they honour this: MadelineProto replays what it stored, and the official
     * Android client answers too, replaying messages lost more than an hour earlier. TDLib is
     * the exception and ignores the request outright, its handler being a bare {@code return
     * Status::OK()}, so an answer is worth asking for but never worth waiting for.
     *
     * <p> Repeats of a range already asked for are skipped: every message stuck behind a gap
     * would otherwise send one, and the ranges nest, so a peer that is already replaying gets
     * asked again for what it is in the middle of sending.
     *
     * <p> Being muted costs nothing but time: the message that prompted the request is held
     * either way, and {@link #skipGap(int)} remains the way out when no resend is ever coming.
     */
    private Mono<Void> requestResend(SecretChatState state, int fromSeqNo, int toSeqNo) {
        var limit = resendLimits.computeIfAbsent(state.id(), id -> new ResendLimit());
        if (limit.covers(fromSeqNo, toSeqNo)) {
            log.debug("Secret chat {} has already asked for {}..{}", state.id(), fromSeqNo, toSeqNo);
            return Mono.empty();
        }
        if (!limit.allow(Instant.now())) {
            log.warn("Secret chat {} has asked for resends too often, not asking again for {}",
                    state.id(), RESEND_COOLDOWN);
            return Mono.empty();
        }

        limit.asked(fromSeqNo, toSeqNo);

        var seqNo = state.seqNo();
        return sendService(state, ImmutableDecryptedMessageActionResend.of(
                        seqNo.toRemoteWireSeqNo(fromSeqNo), seqNo.toRemoteWireSeqNo(toSeqNo)))
                .onErrorResume(e -> {
                    log.warn("Failed to ask secret chat {} for a resend", state.id(), e);
                    return Mono.empty();
                })
                .then();
    }

    /** Delivers whatever the newly filled gap has unblocked, in order. */
    /**
     * Hands on the message the counters are now waiting for, if it arrived early and was held.
     *
     * <p> Called after every message that moves the counters, so closing a gap releases what
     * queued up behind it, one after another, each release exposing the next.
     */
    private Flux<DecryptedMessage> releaseHeldMessages(SecretChatState state) {
        var held = pending.get(state.id());
        if (held == null) {
            return Flux.empty();
        }

        var next = held.remove(state.seqNo().inSeqNo());
        if (next == null) {
            return Flux.empty();
        }

        log.debug("Secret chat {} resumes with the held message {}", state.id(), state.seqNo().inSeqNo());
        return handleDecryptedMessage(state, next);
    }

    private Flux<DecryptedMessage> decrypt(SecretChatState state, EncryptedMessage message) {
        var key = state.key();
        if (state.status() != SecretChatState.Status.READY || key == null) {
            // includes chats the peer discarded: a message arriving afterwards is dropped rather
            // than taken for the start of a new conversation
            log.warn("Dropping message for secret chat {}, which is {}", state.id(), state.status());
            return Flux.empty();
        }

        // a replacement is not instantaneous: messages the peer sent before it processed our
        // commit are still under the old key, and the fingerprint in the payload says which
        var payload = message.bytes();
        var oldKey = state.oldKey();
        if (oldKey != null && payload.readableBytes() >= 8
                && payload.getLongLE(payload.readerIndex()) == oldKey.id()) {
            key = oldKey;
        }

        var decrypted = new SecretChatCipher(acceptLegacyMTProto)
                .decrypt(key, state.creator(), payload);
        if (!(decrypted instanceof DecryptedMessageLayer layer)) {
            // layer 8 wrapped the message directly, without sequence numbers to check
            throw new SecretChatException("Unsupported end-to-end object: " + decrypted);
        }

        return handleDecryptedMessage(state, layer);
    }

    /**
     * Decides what a message is, and either drops it, holds it, or hands it to {@link #deliver}.
     *
     * <p> Only the counters decide: a message is in order, already seen, or too early. Everything
     * that follows from actually having the message lives in {@code deliver}, which is the only
     * part {@link #releaseHeldMessages(SecretChatState)} can reach, since a message taken off the queue is by
     * construction the one the counters are waiting for.
     */
    private Flux<DecryptedMessage> handleDecryptedMessage(SecretChatState state,
        DecryptedMessageLayer layer) {
        var incoming = state.seqNo().accept(layer.inSeqNo(), layer.outSeqNo());
        // kept even for a message we do not deliver: what it reports about the peer's progress
        // is true regardless of whether we could use the message itself
        var builder = state.toBuilder().seqNo(incoming.next());

        return switch (incoming.status()) {
            case REPEATED -> {
                log.debug("Dropping repeated message {} in secret chat {}", incoming.seqNo(), state.id());
                yield store.updateSecretChat(builder.build()).thenMany(Flux.empty());
            }
            case GAP -> {
                // held rather than dropped: the sequence numbers only advance once the hole is
                // filled, so discarding it would end the chat rather than delay one message
                var held = pending.computeIfAbsent(state.id(), id -> new ConcurrentSkipListMap<>());
                if (held.size() >= MAX_HELD_MESSAGES && !held.containsKey(incoming.seqNo())) {
                    // the ones already held are closer to the hole and will be delivered first,
                    // so the newcomer is what gives way. It becomes a gap of its own later, which
                    // skipGap can step over like any other
                    log.warn("Secret chat {} is holding {} messages, dropping message {}",
                            state.id(), held.size(), incoming.seqNo());
                } else {
                    held.putIfAbsent(incoming.seqNo(), layer);
                }

                int missingFrom = state.seqNo().inSeqNo();
                log.warn("Message {} in secret chat {} arrives before {}, holding it and asking for {}..{}",
                        incoming.seqNo(), state.id(), missingFrom, missingFrom, incoming.seqNo() - 1);

                var waiting = builder.build();
                yield store.updateSecretChat(waiting)
                        .then(requestResend(waiting, missingFrom, incoming.seqNo() - 1))
                        .thenMany(Flux.empty());
            }
            case EXPECTED -> {
                // the chat is moving again, so whatever was asked for is settled
                resendLimits.remove(state.id());
                yield deliver(state, builder, layer);
            }
        };
    }

    /**
     * Handles a message which is the one the counters were waiting for.
     *
     * @param builder The state this message produced, with the counters already advanced.
     */
    private Flux<DecryptedMessage> deliver(SecretChatState state, SecretChatState.Builder builder,
                                           DecryptedMessageLayer layer) {
        // any message tells us the layer, not only an explicit notification
        if (layer.layer() > state.layer()) {
            builder.layer(layer.layer());
        }
        builder.remainingMessages(Math.max(0, state.remainingMessages() - 1));

        var inner = layer.message();
        if (!(inner instanceof DecryptedMessageService serviceMessage)) {
            var updated = builder.build();
            return store.updateSecretChat(updated)
                    .then(rekeyIfWorn(updated))
                    // this message may have been the one a later one was waiting for
                    .thenMany(Flux.concat(Flux.just(inner), Flux.defer(() -> releaseHeldMessages(updated))));
        }

        var action = serviceMessage.action();
        // a key replacement answers the peer, so it takes over the state this message produced
        // rather than being folded into the builder
        var rekeyed = rekeyAction(builder.build(), action);
        if (rekeyed != null) {
            return rekeyed.flatMapMany(this::releaseHeldMessages);
        }

        applyAction(builder, state, action);
        var updated = builder.build();
        return store.updateSecretChat(updated)
                .then(rekeyIfWorn(updated))
                .thenMany(Flux.defer(() -> releaseHeldMessages(updated)));
    }

    // service actions change the chat rather than being delivered to the caller
    private void applyAction(SecretChatState.Builder builder, SecretChatState state,
                             DecryptedMessageAction action) {
        switch (action.identifier()) {
            case DecryptedMessageActionNotifyLayer.ID -> {
                int announced = ((DecryptedMessageActionNotifyLayer) action).layer();
                if (announced > state.layer()) {
                    builder.layer(announced);
                }
            }
            case DecryptedMessageActionSetMessageTTL.ID ->
                    builder.ttl(((DecryptedMessageActionSetMessageTTL) action).ttlSeconds());
            default -> log.debug("Unhandled service action in secret chat {}: {}", state.id(), action);
        }
    }

    // the actions of a key replacement, which answer the peer and so cannot be applied to the
    // builder alone; each returns the state it leaves behind, already persisted
    @Nullable
    private Mono<SecretChatState> rekeyAction(SecretChatState state, DecryptedMessageAction action) {
        return switch (action.identifier()) {
            case DecryptedMessageActionRequestKey.ID ->
                    onRequestKey(state, (DecryptedMessageActionRequestKey) action);
            case DecryptedMessageActionAcceptKey.ID ->
                    onAcceptKey(state, (DecryptedMessageActionAcceptKey) action);
            case DecryptedMessageActionCommitKey.ID ->
                    onCommitKey(state, (DecryptedMessageActionCommitKey) action);
            case DecryptedMessageActionAbortKey.ID -> {
                log.debug("Peer aborted the key replacement in secret chat {}", state.id());
                var idle = state.toBuilder().rekey(RekeyState.idle()).build();
                yield store.updateSecretChat(idle).thenReturn(idle);
            }
            default -> null;
        };
    }

    /** How long a key may stay in use however few messages it carries. */
    private static final Duration MAX_KEY_AGE = Duration.ofDays(7);
    /** How long to wait before starting another unprompted key replacement in the same chat. */
    private static final Duration REKEY_RETRY_INTERVAL = Duration.ofMinutes(5);

    private final Map<Integer, Instant> rekeyNotBefore = new ConcurrentHashMap<>();

    /**
     * Asks for a replacement when the current key has carried enough messages or stood long
     * enough, which is what makes the replacement automatic rather than something a caller has
     * to remember.
     */
    private Mono<Void> rekeyIfWorn(SecretChatState state) {
        if (state.rekey().status() != RekeyState.Status.IDLE
                || state.status() != SecretChatState.Status.READY) {
            return Mono.empty();
        }

        var createdAt = state.keyCreatedAt();
        boolean worn = state.remainingMessages() <= 0
                || createdAt != null && createdAt.plus(MAX_KEY_AGE).isBefore(Instant.now());
        if (!worn) {
            return Mono.empty();
        }

        var notBefore = rekeyNotBefore.get(state.id());
        var now = Instant.now();
        if (notBefore != null && now.isBefore(notBefore)) {
            return Mono.empty();
        }
        // a peer that never answers would otherwise have us start one per message, since a chat
        // whose key is worn stays worn until a replacement completes
        rekeyNotBefore.put(state.id(), now.plus(REKEY_RETRY_INTERVAL));

        log.debug("Key of secret chat {} is worn out, replacing it", state.id());
        // a failure here must not fail the message that prompted it: the chat keeps working on
        // the old key, and the next message tries again
        return rekey(state.id())
                .onErrorResume(e -> {
                    log.warn("Failed to start replacing the key of secret chat {}", state.id(), e);
                    return Mono.empty();
                });
    }

    /**
     * Replaces the key of a chat, so that a key which leaks exposes only the messages around it.
     *
     * <p> Called on its own when the current key wears out, so a caller only needs this to force
     * a replacement earlier. Does nothing if one is already in progress.
     *
     * @param chatId The id of the chat.
     * @return A {@link Mono} completing when the request has been sent.
     */
    public Mono<Void> rekey(int chatId) {
        return withChat(chatId, state -> {
            if (state.rekey().status() != RekeyState.Status.IDLE) {
                return Mono.empty();
            }
            return dhParameters().flatMap(dh -> {
                var secret = DhParameters.generateSecret();
                var gA = dh.computePublicKeyData(secret);
                long exchangeId = random.nextLong();

                var next = state.toBuilder()
                        .rekey(RekeyState.requested(exchangeId, secret))
                        .build();

                log.info("Requesting a new key for secret chat {}, exchange 0x{}",
                        chatId, Long.toHexString(exchangeId));
                return sendService(next, ImmutableDecryptedMessageActionRequestKey.of(exchangeId, gA));
            });
        });
    }

    // the peer wants a new key
    private Mono<SecretChatState> onRequestKey(SecretChatState state, DecryptedMessageActionRequestKey request) {
        long exchangeId = request.exchangeId();
        var rekey = state.rekey();

        if (rekey.tiesWith(exchangeId)) {
            // both sides drew the same number, so neither proceeds
            log.warn("Both sides asked to replace the key of secret chat {} with the same exchange id",
                    state.id());
            var idle = state.toBuilder().rekey(RekeyState.idle()).build();
            return store.updateSecretChat(idle).thenReturn(idle);
        }
        if (rekey.status() != RekeyState.Status.IDLE && !rekey.isOutrankedBy(exchangeId)) {
            log.debug("Ignoring the peer's key replacement in secret chat {}, ours outranks it", state.id());
            return store.updateSecretChat(state).thenReturn(state);
        }

        return dhParameters().flatMap(dh -> {
            var secret = DhParameters.generateSecret();
            var gB = dh.computePublicKeyData(secret);
            var pendingKey = SecretChatKeyExchange.deriveKey(dh, request.gA(), secret);

            var next = state.toBuilder()
                    .rekey(RekeyState.accepted(exchangeId, pendingKey))
                    .build();

            log.info("Accepting a new key for secret chat {}, exchange 0x{}",
                    state.id(), Long.toHexString(exchangeId));
            return sendService(next, ImmutableDecryptedMessageActionAcceptKey.of(
                    exchangeId, gB, pendingKey.id()));
        });
    }

    // the peer answered the replacement we asked for
    private Mono<SecretChatState> onAcceptKey(SecretChatState state, DecryptedMessageActionAcceptKey accept) {
        long exchangeId = accept.exchangeId();
        var rekey = state.rekey();
        var secret = rekey.secret();

        if (rekey.status() != RekeyState.Status.REQUESTED || rekey.exchangeId() != exchangeId || secret == null) {
            log.debug("Ignoring acceptKey for an exchange we are not running in secret chat {}", state.id());
            var idle = state.toBuilder().rekey(RekeyState.idle()).build();
            return store.updateSecretChat(idle).thenReturn(idle);
        }

        return dhParameters().flatMap(dh -> {
            AuthKey replacement;
            try {
                replacement = SecretChatKeyExchange.deriveKey(dh, accept.gB(), secret, accept.keyFingerprint());
            } catch (SecretChatException e) {
                log.warn("Aborting the key replacement in secret chat {}: {}", state.id(), e.getMessage());
                return sendService(state.toBuilder().rekey(RekeyState.idle()).build(),
                                ImmutableDecryptedMessageActionAbortKey.of(exchangeId))
                        .then(Mono.error(e));
            }

            // the key is stored before the commit goes out. The other order loses the chat: the
            // peer switches on receiving the commit, and a crash before we stored the key leaves
            // us with no way to derive it again and nothing the peer sends readable
            var next = state.toBuilder()
                    .key(replacement, Instant.now())
                    .rekey(RekeyState.idle())
                    .build();

            log.info("Committing the new key of secret chat {}, fingerprint 0x{}", state.id(),
                    Long.toHexString(replacement.id()));
            return sendService(next, ImmutableDecryptedMessageActionCommitKey.of(
                    exchangeId, replacement.id()), state.key());
        });
    }

    // the peer confirms the replacement we accepted
    private Mono<SecretChatState> onCommitKey(SecretChatState state, DecryptedMessageActionCommitKey commit) {
        long exchangeId = commit.exchangeId();
        var rekey = state.rekey();
        var pendingKey = rekey.pendingKey();

        if (rekey.status() != RekeyState.Status.ACCEPTED || rekey.exchangeId() != exchangeId || pendingKey == null) {
            log.debug("Ignoring commitKey for an exchange we are not running in secret chat {}", state.id());
            return store.updateSecretChat(state).thenReturn(state);
        }
        if (pendingKey.id() != commit.keyFingerprint()) {
            log.warn("Aborting the key replacement in secret chat {}: peer committed a key we did not derive",
                    state.id());
            return sendService(state.toBuilder().rekey(RekeyState.idle()).build(),
                            ImmutableDecryptedMessageActionAbortKey.of(exchangeId))
                    .then(Mono.error(new SecretChatException("Committed key fingerprint mismatch")));
        }

        var next = state.toBuilder()
                .key(pendingKey, Instant.now())
                .rekey(RekeyState.idle())
                .build();

        // a message under the new key, so the peer sees the switch took effect
        log.info("Secret chat {} now uses its replacement key, fingerprint 0x{}", state.id(),
                Long.toHexString(pendingKey.id()));
        return sendService(next, DecryptedMessageActionNoop.instance());
    }

    private Mono<SecretChatState> sendService(SecretChatState state, DecryptedMessageAction action) {
        return sendService(state, action, null);
    }

    private Mono<SecretChatState> sendService(SecretChatState state, DecryptedMessageAction action,
                                              @Nullable AuthKey with) {
        return send(state, DecryptedMessageService.builder()
                .randomId(random.nextLong())
                .action(action)
                .build(), true, with);
    }

    /**
     * Tells the peer which layer we speak, so that it stops holding back on features and, for
     * peers which open a chat in MTProto 1.0, switches to 2.0.
     */
    private Mono<SecretChatState> notifyLayer(SecretChatState state) {
        return send(state, DecryptedMessageService.builder()
                .randomId(random.nextLong())
                .action(ImmutableDecryptedMessageActionNotifyLayer.of(LAYER))
                .build(), true);
    }

    private Mono<SecretChatState> send(SecretChatState state, DecryptedMessage message, boolean serviceMessage) {
        return send(state, message, serviceMessage, null);
    }

    /**
     * @param with the key to encrypt with, when it must not be the chat's current one. Only
     * {@code commitKey} needs this: it is what makes the peer switch, so it has to arrive under
     * the key the peer still holds, while we already hold the replacement.
     */
    private Mono<SecretChatState> send(SecretChatState state, DecryptedMessage message,
                                       boolean serviceMessage, @Nullable AuthKey with) {
        var key = with != null ? with : state.key();
        if (state.status() != SecretChatState.Status.READY || key == null) {
            return Mono.error(new SecretChatException(
                    "Secret chat " + state.id() + " is not ready, it is " + state.status()));
        }

        byte[] randomBytes = new byte[RANDOM_BYTES];
        random.nextBytes(randomBytes);

        var allocated = state.seqNo().allocate();
        var layer = DecryptedMessageLayer.builder()
                .randomBytes(Unpooled.wrappedBuffer(randomBytes))
                .layer(negotiatedLayer(state))
                .inSeqNo(allocated.inSeqNo())
                .outSeqNo(allocated.outSeqNo())
                .message(message)
                .build();

        ByteBuf payload = new SecretChatCipher(acceptLegacyMTProto)
                .encrypt(key, state.creator(), layer);
        long randomId = random.nextLong();
        var peer = ImmutableInputEncryptedChat.of(state.id(), state.accessHash());

        var next = state.toBuilder()
                .seqNo(allocated.next())
                .remainingMessages(Math.max(0, state.remainingMessages() - 1))
                .build();

        // the counter reaches the disk before the message that carries it reaches the peer.
        // The other order loses the chat: after a crash we would hand out a sequence number the
        // peer has already seen, and it discards the chat rather than guess what we meant
        return store.updateSecretChat(next)
                // the request is built on subscription, so the payload has to outlive this method
                .then(Mono.defer(() -> serviceMessage
                        ? service.sendEncryptedService(peer, randomId, payload)
                        : service.sendEncrypted(ImmutableSendEncrypted.of(0, peer, randomId, payload))))
                .doFinally(signal -> payload.release())
                .thenReturn(next);
    }

    private Mono<Void> withChat(int chatId, java.util.function.Function<SecretChatState, Mono<?>> action) {
        return store.getSecretChat(chatId)
                .switchIfEmpty(Mono.error(() -> new SecretChatException("No secret chat with id " + chatId)))
                .flatMap(action)
                .then();
    }

    // neither side gains from claiming a layer the other cannot read
    private static int negotiatedLayer(SecretChatState state) {
        return Math.min(LAYER, Math.max(state.layer(), SecretChatState.DEFAULT_LAYER));
    }

    // the peer asked us to open a chat: derive the key from its half and answer with ours
    private Mono<SecretChatState> accept(EncryptedChatRequested requested) {
        return dhParameters().flatMap(dh -> {
            var secret = DhParameters.generateSecret();
            var gB = dh.computePublicKeyData(secret);
            var key = SecretChatKeyExchange.deriveKey(dh, requested.gA(), secret);

            var state = SecretChatState.builder(requested.id(), requested.accessHash(),
                            requested.adminId(), false)
                    .status(SecretChatState.Status.READY)
                    .key(key, Instant.now())
                    .build();

            // stored before the answer goes out: acceptEncryption makes the chat real for the
            // peer, and a crash in between would leave it holding a key we no longer have
            return store.updateSecretChat(state)
                    .then(service.acceptEncryption(
                            ImmutableInputEncryptedChat.of(requested.id(), requested.accessHash()),
                            gB, key.id()))
                    .doOnNext(c -> log.debug("Accepted secret chat {} from user {}",
                            requested.id(), requested.adminId()))
                    .then(notifyLayer(state));
        });
    }

    // the peer accepted the chat we asked for: finish the exchange with the exponent we kept
    private Mono<SecretChatState> complete(BaseEncryptedChat accepted) {
        return store.getSecretChat(accepted.id())
                .switchIfEmpty(Mono.error(() -> new SecretChatException(
                        "No pending secret chat with id " + accepted.id())))
                .flatMap(state -> {
                    if (state.status() != SecretChatState.Status.REQUESTED || state.secret() == null) {
                        // a repeated update for a chat already keyed; nothing left to do
                        log.debug("Ignoring acceptance of secret chat {} in state {}",
                                accepted.id(), state.status());
                        return Mono.empty();
                    }

                    return dhParameters().flatMap(dh -> {
                        var key = SecretChatKeyExchange.deriveKey(dh, accepted.gAOrB(),
                                state.secret(), accepted.keyFingerprint());

                        var keyed = state.toBuilder()
                                .key(key, Instant.now())
                                .status(SecretChatState.Status.READY)
                                .build();

                        log.debug("Secret chat {} accepted by user {}", accepted.id(), accepted.participantId());
                        return store.updateSecretChat(keyed)
                                .then(notifyLayer(keyed));
                    });
                });
    }

    private Mono<SecretChatState> discarded(EncryptedChatDiscarded discarded) {
        return store.getSecretChat(discarded.id())
                .flatMap(state -> {
                    var gone = state.toBuilder().status(SecretChatState.Status.DISCARDED).build();
                    log.debug("Secret chat {} discarded by the peer", discarded.id());
                    // the state is kept rather than deleted so that late messages are dropped
                    // instead of being taken for the start of a new chat
                    return store.updateSecretChat(gone).thenReturn(gone);
                });
    }

    /**
     * The parameters every secret chat of this account shares.
     *
     * <p> They change only when the server bumps the version, which is why the request quotes the
     * one we hold and may be answered with nothing at all.
     *
     * <p> TODO skip the request entirely for a while once the parameters are known. Nothing about
     * that looks problematic: the {@code version} field is the change signal, so a stale cache is
     * noticed on the next fetch rather than silently; the request always goes to the main DC, so
     * reconnecting elsewhere cannot hand us a different answer; and the prime built into
     * {@link DhPrimeCheckerCache} is the one Telegram has been returning for years. The cost of
     * being stale is a chat that cannot be keyed until the next fetch. Left alone for now because
     * this runs only when a chat is created, accepted or rekeyed, which is rare enough that the
     * round trip does not matter.
     */
    private Mono<DhParameters> dhParameters() {
        return Mono.defer(() -> {
            // no server randomness is requested: the exponents come from SecureRandom, and mixing
            // in bytes the server chose would not make them any less predictable to the server
            return service.getDhConfig(dhVersion, 0)
                    .map(config -> switch (config.identifier()) {
                        case BaseDhConfig.ID -> {
                            var received = (BaseDhConfig) config;
                            var params = DhParameters.create(received.p(), received.g(), primeChecker);
                            parameters = params;
                            dhVersion = received.version();
                            yield params;
                        }
                        case DhConfigNotModified.ID -> {
                            var cached = parameters;
                            if (cached == null) {
                                throw new SecretChatException(
                                        "Server reports unchanged DH config, but none is cached");
                            }
                            yield cached;
                        }
                        default -> throw new SecretChatException("Unexpected DhConfig: " + config);
                    });
        });
    }

    /**
     * How often a chat has recently asked the peer to resend something.
     *
     * <p> A resend request is itself a message with its own sequence number, so it can create a
     * gap on the far side and provoke a request back. Two clients that have each lost something
     * will then keep asking each other forever, which is traffic Telegram sees and we do not
     * want to be the source of. The counter is cleared by any message that arrives in order,
     * since that means the chat is working and the asking was worth it.
     */
    private static final class ResendLimit {
        Instant windowStartedAt = Instant.now();
        int attempts;
        @Nullable
        Instant mutedUntil;
        int askedFrom = -1;
        int askedTo = -1;

        /** {@return Whether the last request already covers this range} */
        synchronized boolean covers(int from, int to) {
            return askedFrom >= 0 && from >= askedFrom && to <= askedTo;
        }

        synchronized void asked(int from, int to) {
            askedFrom = askedFrom < 0 ? from : Math.min(askedFrom, from);
            askedTo = Math.max(askedTo, to);
        }

        synchronized boolean allow(Instant now) {
            if (mutedUntil != null) {
                if (now.isBefore(mutedUntil)) {
                    return false;
                }
                mutedUntil = null;
                windowStartedAt = now;
                attempts = 0;
            }
            if (windowStartedAt.plus(RESEND_WINDOW).isBefore(now)) {
                windowStartedAt = now;
                attempts = 0;
            }
            if (++attempts > MAX_RESENDS) {
                mutedUntil = now.plus(RESEND_COOLDOWN);
                return false;
            }
            return true;
        }
    }
}
