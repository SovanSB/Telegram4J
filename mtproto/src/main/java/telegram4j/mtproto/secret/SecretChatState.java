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

import reactor.util.annotation.Nullable;
import telegram4j.mtproto.auth.AuthKey;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Everything about one secret chat that must outlive the process.
 *
 * <p> Secret chats are not stored server-side, so this state is the chat. Losing it loses the
 * conversation with no way to recover it from the server, and losing only part of it is worse
 * than losing all of it: a chat whose key survived but whose {@link #seqNo() counters} did not
 * will be discarded by the peer as soon as it speaks.
 *
 * @implNote Instances are mutable and not thread safe. All access to one chat is expected to be
 * serialized, as it is in the reference implementations, where a chat is owned by a single actor.
 */
public final class SecretChatState {

    /** Where a chat is in its lifecycle. */
    public enum Status {
        /**
         * We sent {@code messages.requestEncryption} and the peer has not answered yet.
         * {@link #secret()} is set and {@link #key()} is not.
         *
         * <p> A request can sit here for as long as the peer takes to open the chat, so the
         * secret is persisted rather than kept in memory; a restart in between would otherwise
         * leave a chat the peer can accept but we can never key.
         */
        REQUESTED,
        /** The key is negotiated and the chat can carry messages. */
        READY,
        /** Discarded by either side. Kept so that late messages are dropped rather than reprocessed. */
        DISCARDED
    }

    /** The layer to assume for a peer which has not told us its own yet. */
    public static final int DEFAULT_LAYER = 46;
    /** Messages a key may carry before it must be replaced, as in TDLib and MadelineProto. */
    public static final int DEFAULT_MESSAGES_PER_KEY = 100;

    private final int id;
    private final long accessHash;
    private final long peerId;
    private final boolean creator;

    private Status status;
    @Nullable
    private BigInteger secret;
    @Nullable
    private AuthKey key;
    @Nullable
    private AuthKey oldKey;
    private Instant keyCreatedAt;
    private int remainingMessages = DEFAULT_MESSAGES_PER_KEY;
    private int layer = DEFAULT_LAYER;
    private int ttl;
    private final SeqNoState seqNo;
    private RekeyState rekey = RekeyState.idle();

    public SecretChatState(int id, long accessHash, long peerId, boolean creator,
                           Status status, SeqNoState seqNo) {
        this.id = id;
        this.accessHash = accessHash;
        this.peerId = peerId;
        this.creator = creator;
        this.status = status;
        this.seqNo = seqNo;
    }

    /** {@return The {@code chat_id}, unique per account} */
    public int id() {
        return id;
    }

    public long accessHash() {
        return accessHash;
    }

    /** {@return The id of the other participant} */
    public long peerId() {
        return peerId;
    }

    /**
     * {@return Whether this chat was created by us}
     *
     * <p> Decides the parity of the {@linkplain SeqNoState sequence numbers} and the offset of
     * the key derivation, so it must be persisted rather than recomputed: it is not derivable
     * from the state alone once the {@code admin_id} is no longer at hand.
     */
    public boolean creator() {
        return creator;
    }

    public Status status() {
        return status;
    }

    public void status(Status status) {
        this.status = status;
    }

    /** {@return Our private exponent, while the chat is {@link Status#REQUESTED}} */
    @Nullable
    public BigInteger secret() {
        return secret;
    }

    public void secret(@Nullable BigInteger secret) {
        this.secret = secret;
    }

    /** {@return The negotiated key, once the chat is {@link Status#READY}} */
    @Nullable
    public AuthKey key() {
        return key;
    }

    /**
     * Installs a newly negotiated key, keeping the previous one, and restarts the counters which
     * decide when to replace it again.
     *
     * <p> The old key is kept because a replacement is not instantaneous: messages the peer sent
     * before it processed our commit are still encrypted with it, and arrive after.
     *
     * <p> The private exponent is dropped here: it exists only to reach this point, and keeping
     * it afterwards would leave the material to re-derive the key sitting in storage for the
     * lifetime of the chat.
     */
    public void key(AuthKey key, Instant createdAt) {
        this.oldKey = this.key;
        this.key = key;
        this.keyCreatedAt = createdAt;
        this.remainingMessages = DEFAULT_MESSAGES_PER_KEY;
        this.secret = null;
    }

    /** {@return The key replaced by the last rekey, still accepted for messages already in flight} */
    @Nullable
    public AuthKey oldKey() {
        return oldKey;
    }

    /** Sets the previous key, or clears it once the peer is known to have moved on. */
    public void oldKey(@Nullable AuthKey oldKey) {
        this.oldKey = oldKey;
    }

    public Instant keyCreatedAt() {
        return keyCreatedAt;
    }

    /** {@return How many more messages this key may carry before it must be replaced} */
    public int remainingMessages() {
        return remainingMessages;
    }

    public void remainingMessages(int remainingMessages) {
        this.remainingMessages = remainingMessages;
    }

    /**
     * {@return The highest layer the peer has told us it supports}
     *
     * <p> Starts at {@value #DEFAULT_LAYER} and only ever grows. Both an explicit
     * {@code decryptedMessageActionNotifyLayer} and the {@code layer} of any received
     * {@code decryptedMessageLayer} count as being told.
     */
    public int layer() {
        return layer;
    }

    public void layer(int layer) {
        this.layer = layer;
    }

    /** {@return The self-destruct timer of new messages, in seconds, or zero when disabled} */
    public int ttl() {
        return ttl;
    }

    public void ttl(int ttl) {
        this.ttl = ttl;
    }

    public SeqNoState seqNo() {
        return seqNo;
    }

    public RekeyState rekey() {
        return rekey;
    }

    public void rekey(RekeyState rekey) {
        this.rekey = rekey;
    }

    @Override
    public String toString() {
        return "SecretChatState{id=" + id + ", status=" + status + ", creator=" + creator +
                ", layer=" + layer + ", " + seqNo + '}';
    }
}
