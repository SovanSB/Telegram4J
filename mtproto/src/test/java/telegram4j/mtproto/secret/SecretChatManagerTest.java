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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import telegram4j.mtproto.DcId;
import telegram4j.mtproto.auth.TestDhParameters;
import telegram4j.mtproto.client.MTProtoClient;
import telegram4j.mtproto.client.MTProtoClientGroup;
import telegram4j.mtproto.client.UpdateDispatcher;
import telegram4j.mtproto.service.ChatService;
import telegram4j.mtproto.store.SecretChatStore;
import telegram4j.mtproto.store.StoreLayoutImpl;
import telegram4j.tl.*;
import telegram4j.tl.api.TlMethod;
import telegram4j.tl.messages.ImmutableBaseDhConfig;
import telegram4j.tl.messages.ImmutableBaseSentEncryptedMessage;
import telegram4j.tl.request.messages.AcceptEncryption;
import telegram4j.tl.request.messages.DiscardEncryption;
import telegram4j.tl.request.messages.GetDhConfig;
import telegram4j.tl.request.messages.RequestEncryption;
import telegram4j.tl.request.messages.SendEncrypted;
import telegram4j.tl.request.messages.SendEncryptedService;
import telegram4j.tl.secret.BaseDecryptedMessage;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drives both halves of the exchange against a stand-in for the server, so the flow that only
 * ever runs across two devices can be checked without either.
 */
class SecretChatManagerTest {

    static final long INITIATOR = 1111L;
    static final long PARTICIPANT = 2222L;
    static final int CHAT_ID = 4242;
    static final long ACCESS_HASH = 0x1122334455667788L;

    /** Answers the four requests the exchange makes, and remembers what it was told. */
    static final class FakeServer implements MTProtoClientGroup {
        final List<TlMethod<?>> requests = new ArrayList<>();
        /** What each side put on the wire, in order, for the other to be handed. */
        final List<EncryptedMessage> delivered = new ArrayList<>();
        ByteBuf gA;
        ByteBuf gB;
        long acceptedFingerprint;
        boolean discarded;

        @SuppressWarnings("unchecked")
        @Override
        public <R> Mono<R> send(DcId id, TlMethod<? extends R> method) {
            requests.add(method);
            return Mono.fromSupplier(() -> {
                if (method instanceof GetDhConfig) {
                    return (R) ImmutableBaseDhConfig.of(TestDhParameters.G,
                            Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(TestDhParameters.PRIME)), 42,
                            Unpooled.EMPTY_BUFFER);
                }
                if (method instanceof RequestEncryption request) {
                    gA = request.gA();
                    return (R) ImmutableEncryptedChatWaiting.of(CHAT_ID, ACCESS_HASH, 0, INITIATOR, PARTICIPANT);
                }
                if (method instanceof AcceptEncryption request) {
                    gB = request.gB();
                    acceptedFingerprint = request.keyFingerprint();
                    return (R) ImmutableBaseEncryptedChat.of(CHAT_ID, ACCESS_HASH, 0, INITIATOR, PARTICIPANT,
                            gB, acceptedFingerprint);
                }
                if (method instanceof SendEncrypted request) {
                    delivered.add(ImmutableBaseEncryptedMessage.of(request.randomId(), CHAT_ID, 0,
                            request.data(), EncryptedFileEmpty.instance()));
                    return (R) ImmutableBaseSentEncryptedMessage.of(0);
                }
                if (method instanceof SendEncryptedService request) {
                    delivered.add(ImmutableEncryptedMessageService.of(request.randomId(), CHAT_ID, 0,
                            request.data()));
                    return (R) ImmutableBaseSentEncryptedMessage.of(0);
                }
                if (method instanceof DiscardEncryption) {
                    discarded = true;
                    return (R) Boolean.TRUE;
                }
                throw new AssertionError("Unexpected request: " + method);
            });
        }

        @Override public MTProtoClient main() { throw new UnsupportedOperationException(); }
        @Override public UpdateDispatcher updates() { throw new UnsupportedOperationException(); }
        @Override public Mono<Void> start() { return Mono.empty(); }
        @Override public Mono<Void> close() { return Mono.empty(); }
        @Override public Mono<MTProtoClient> getOrCreateClient(DcId id) { throw new UnsupportedOperationException(); }
    }

    static SecretChatStore store() {
        return new StoreLayoutImpl(c -> c);
    }

    static SecretChatManager manager(FakeServer server, SecretChatStore store) {
        return new SecretChatManager(new ChatService(server, (StoreLayoutImpl) store), store);
    }

    @Test
    void bothSidesEndUpWithTheSameKey() {
        var server = new FakeServer();
        var initiatorStore = store();
        var participantStore = store();

        var initiator = manager(server, initiatorStore);
        var participant = manager(server, participantStore);

        // the initiator asks for a chat and gets back something not yet usable
        var requested = initiator.requestSecretChat(ImmutableBaseInputUser.of(PARTICIPANT, 0)).block();
        assertNotNull(requested);
        assertEquals(SecretChatState.Status.REQUESTED, requested.status());
        assertNull(requested.key());
        assertNotNull(requested.secret(), "the exponent is needed to finish the exchange later");
        assertTrue(requested.creator());

        // the participant sees the request and accepts it, which keys its side immediately
        var accepted = participant.onUpdate(ImmutableEncryptedChatRequested.builder()
                .id(CHAT_ID)
                .accessHash(ACCESS_HASH)
                .date(0)
                .adminId(INITIATOR)
                .participantId(PARTICIPANT)
                .gA(server.gA)
                .build()).block();
        assertNotNull(accepted);
        assertEquals(SecretChatState.Status.READY, accepted.status());
        assertFalse(accepted.creator());
        assertNotNull(accepted.key());

        // and the initiator finishes with the exponent it kept
        var completed = initiator.onUpdate(ImmutableBaseEncryptedChat.of(CHAT_ID, ACCESS_HASH, 0,
                INITIATOR, PARTICIPANT, server.gB, server.acceptedFingerprint)).block();
        assertNotNull(completed);
        assertEquals(SecretChatState.Status.READY, completed.status());
        assertNotNull(completed.key());
        assertNull(completed.secret(), "the exponent outlived its purpose");

        assertEquals(accepted.key().id(), completed.key().id());
        assertEquals(accepted.key().value(), completed.key().value());

        // both sides persisted what they derived
        assertEquals(completed.key().id(), initiatorStore.getSecretChat(CHAT_ID).block().key().id());
        assertEquals(accepted.key().id(), participantStore.getSecretChat(CHAT_ID).block().key().id());
    }

    /** Runs the whole exchange and hands back the two keyed managers. */
    static Keyed keyed(FakeServer server) {
        var initiator = manager(server, store());
        var participant = manager(server, store());

        initiator.requestSecretChat(ImmutableBaseInputUser.of(PARTICIPANT, 0)).block();

        // each side announces its layer as soon as it has the key, which spends a sequence
        // number; a real server hands those over, and so must this
        server.delivered.clear();
        participant.onUpdate(ImmutableEncryptedChatRequested.builder()
                .id(CHAT_ID).accessHash(ACCESS_HASH).date(0)
                .adminId(INITIATOR).participantId(PARTICIPANT).gA(server.gA)
                .build()).block();
        var fromParticipant = List.copyOf(server.delivered);

        server.delivered.clear();
        initiator.onUpdate(ImmutableBaseEncryptedChat.of(CHAT_ID, ACCESS_HASH, 0,
                INITIATOR, PARTICIPANT, server.gB, server.acceptedFingerprint)).block();
        var fromInitiator = List.copyOf(server.delivered);

        fromParticipant.forEach(m -> initiator.onNewMessage(m).block());
        fromInitiator.forEach(m -> participant.onNewMessage(m).block());

        return new Keyed(initiator, participant);
    }

    record Keyed(SecretChatManager initiator, SecretChatManager participant) {}

    @Test
    void aMessageWrittenByOneSideReadsOnTheOther() {
        var server = new FakeServer();
        var keyed = keyed(server);

        server.delivered.clear();
        keyed.initiator().sendMessage(CHAT_ID, "hello").block();
        assertEquals(1, server.delivered.size());

        var received = keyed.participant().onNewMessage(server.delivered.get(0)).block();
        assertInstanceOf(BaseDecryptedMessage.class, received);
        assertEquals("hello", ((BaseDecryptedMessage) received).message());
    }

    @Test
    void bothDirectionsWorkAndCountersStayInStep() {
        var server = new FakeServer();
        var keyed = keyed(server);

        for (int i = 0; i < 8; i++) {
            server.delivered.clear();
            keyed.initiator().sendMessage(CHAT_ID, "from initiator " + i).block();
            var toParticipant = keyed.participant().onNewMessage(server.delivered.get(0)).block();
            assertEquals("from initiator " + i, ((BaseDecryptedMessage) toParticipant).message());

            server.delivered.clear();
            keyed.participant().sendMessage(CHAT_ID, "from participant " + i).block();
            var toInitiator = keyed.initiator().onNewMessage(server.delivered.get(0)).block();
            assertEquals("from participant " + i, ((BaseDecryptedMessage) toInitiator).message());
        }
    }

    @Test
    void keyingAnnouncesOurLayer() {
        var server = new FakeServer();
        var initiator = manager(server, store());
        var participantStore = store();
        var participant = manager(server, participantStore);

        initiator.requestSecretChat(ImmutableBaseInputUser.of(PARTICIPANT, 0)).block();

        // accepting sends a notifyLayer, which is what tells a peer holding back on MTProto 1.0
        // that it can stop
        server.delivered.clear();
        participant.onUpdate(ImmutableEncryptedChatRequested.builder()
                .id(CHAT_ID).accessHash(ACCESS_HASH).date(0)
                .adminId(INITIATOR).participantId(PARTICIPANT).gA(server.gA)
                .build()).block();
        assertEquals(1, server.delivered.size());

        var notification = server.delivered.get(0);
        assertInstanceOf(EncryptedMessageService.class, notification);

        initiator.onUpdate(ImmutableBaseEncryptedChat.of(CHAT_ID, ACCESS_HASH, 0,
                INITIATOR, PARTICIPANT, server.gB, server.acceptedFingerprint)).block();

        // it carries no payload for the caller, but it does raise the layer we credit the peer with
        assertNull(initiator.onNewMessage(notification).block());
        var state = initiator.getSecretChats().blockFirst();
        assertNotNull(state);
        assertEquals(SecretChatManager.LAYER, state.layer());
    }

    @Test
    void aRepeatedMessageIsDroppedRatherThanDelivered() {
        var server = new FakeServer();
        var keyed = keyed(server);

        server.delivered.clear();
        keyed.initiator().sendMessage(CHAT_ID, "once").block();
        var message = server.delivered.get(0);

        assertNotNull(keyed.participant().onNewMessage(message).block());
        assertNull(keyed.participant().onNewMessage(message).block(), "the repeat was delivered");
    }

    @Test
    void aMessageArrivingOutOfOrderIsNotDelivered() {
        var server = new FakeServer();
        var keyed = keyed(server);

        server.delivered.clear();
        keyed.initiator().sendMessage(CHAT_ID, "first").block();
        keyed.initiator().sendMessage(CHAT_ID, "second").block();
        assertEquals(2, server.delivered.size());

        // the second arrives alone; it must wait rather than be handed over out of order
        assertNull(keyed.participant().onNewMessage(server.delivered.get(1)).block());

        var first = keyed.participant().onNewMessage(server.delivered.get(0)).block();
        assertEquals("first", ((BaseDecryptedMessage) first).message());
    }

    @Test
    void rejectsAnAcceptanceQuotingTheWrongFingerprint() {
        var server = new FakeServer();
        var initiator = manager(server, store());

        initiator.requestSecretChat(ImmutableBaseInputUser.of(PARTICIPANT, 0)).block();

        var e = assertThrows(SecretChatException.class,
                () -> initiator.onUpdate(ImmutableBaseEncryptedChat.of(CHAT_ID, ACCESS_HASH, 0,
                        INITIATOR, PARTICIPANT, server.gA, 0xdeadbeefL)).block());
        assertTrue(e.getMessage().startsWith("Key fingerprint mismatch"), e.getMessage());
    }

    @Test
    void ignoresARepeatedAcceptance() {
        var server = new FakeServer();
        var initiator = manager(server, store());
        var participant = manager(server, store());

        initiator.requestSecretChat(ImmutableBaseInputUser.of(PARTICIPANT, 0)).block();
        participant.onUpdate(ImmutableEncryptedChatRequested.builder()
                .id(CHAT_ID).accessHash(ACCESS_HASH).date(0)
                .adminId(INITIATOR).participantId(PARTICIPANT).gA(server.gA)
                .build()).block();

        var acceptance = ImmutableBaseEncryptedChat.of(CHAT_ID, ACCESS_HASH, 0,
                INITIATOR, PARTICIPANT, server.gB, server.acceptedFingerprint);
        var first = initiator.onUpdate(acceptance).block();
        assertNotNull(first);

        // the same update again must not rerun the exchange against a spent exponent
        assertNull(initiator.onUpdate(acceptance).block());
    }

    @Test
    void discardingForgetsTheChat() {
        var server = new FakeServer();
        var store = store();
        var initiator = manager(server, store);

        initiator.requestSecretChat(ImmutableBaseInputUser.of(PARTICIPANT, 0)).block();
        initiator.discardSecretChat(CHAT_ID, true).block();

        assertTrue(server.discarded);
        assertNull(store.getSecretChat(CHAT_ID).block());
    }

    @Test
    void aChatDiscardedByThePeerIsKeptAsDiscarded() {
        var server = new FakeServer();
        var store = store();
        var initiator = manager(server, store);

        initiator.requestSecretChat(ImmutableBaseInputUser.of(PARTICIPANT, 0)).block();
        var state = initiator.onUpdate(ImmutableEncryptedChatDiscarded.builder().id(CHAT_ID).build()).block();

        assertNotNull(state);
        assertEquals(SecretChatState.Status.DISCARDED, state.status());
        // kept rather than deleted, so a late message is dropped instead of starting a new chat
        assertNotNull(store.getSecretChat(CHAT_ID).block());
    }
}
