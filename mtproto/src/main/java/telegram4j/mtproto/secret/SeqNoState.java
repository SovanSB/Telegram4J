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

/**
 * The sequence numbers of one secret chat.
 *
 * <p> Both sides count from zero and increment by one per message. The counters are put on the
 * wire as {@code 2 * counter + base}, where the base is 1 for the outgoing counter of the chat
 * creator and 0 for its incoming one, and the other way round for the other participant. The
 * parity is therefore what tells whose message this is, and it is why a message reflected back
 * at its sender does not parse as one of theirs.
 *
 * <p><b>The outgoing counter is owned by this side alone and only ever advances in
 * {@link #allocate()}.</b> An incoming message also carries the peer's own view of how many of
 * our messages it has processed, and it is tempting to adopt that value; doing so silently
 * corrupts the counter, because a peer replying to a message it has not finished processing
 * reports one less than we have sent. Clients differ in when exactly they advance that counter,
 * which makes the resulting drift look like an off-by-one specific to the peer's platform. Here
 * that value is kept apart as {@link #remoteInSeqNo()} and only used to bound-check the peer.
 *
 * <p> Instances are immutable: both operations hand back the state that follows them, so a
 * counter cannot advance without the caller deciding to keep the result.
 *
 * @see <a href="https://core.telegram.org/api/end-to-end/seq_no">Sequence numbers in Secret Chats</a>
 */
public final class SeqNoState {

    /** How an incoming message relates to what we have already processed. */
    public enum Status {
        /** The message is the next one expected. */
        EXPECTED,
        /** The message has already been processed and must be dropped. */
        REPEATED,
        /** Messages before this one are missing; it must be held until they arrive. */
        GAP
    }

    /**
     * The wire values for an outgoing message, and the counters that follow sending it.
     *
     * @param inSeqNo The {@code in_seq_no} to put in the {@code decryptedMessageLayer}.
     * @param outSeqNo The {@code out_seq_no} to put in the {@code decryptedMessageLayer}.
     * @param next The counters to persist, before the message is sent.
     */
    public record Allocated(int inSeqNo, int outSeqNo, SeqNoState next) {}

    /**
     * The classification of an incoming message, and the counters that follow it.
     *
     * @param status What to do with the message.
     * @param seqNo The raw sequence number of the message.
     * @param next The counters to persist. They differ from the previous ones even when the
     * message is {@link Status#REPEATED} or {@link Status#GAP}, since the peer's acknowledgement
     * is recorded either way.
     */
    public record Incoming(Status status, int seqNo, SeqNoState next) {}

    private final boolean creator;
    private final int inBase;
    private final int outBase;

    private final int inSeqNo;
    private final int outSeqNo;
    private final int remoteInSeqNo;

    /**
     * Creates the counters of a chat which has just been established.
     *
     * @param creator whether the chat was created by us, i.e. whether we are its {@code admin_id}.
     */
    public SeqNoState(boolean creator) {
        this(creator, 0, 0, 0);
    }

    /** Restores previously persisted counters. */
    public SeqNoState(boolean creator, int inSeqNo, int outSeqNo, int remoteInSeqNo) {
        this.creator = creator;
        this.inBase = creator ? 0 : 1;
        this.outBase = creator ? 1 : 0;
        this.inSeqNo = inSeqNo;
        this.outSeqNo = outSeqNo;
        this.remoteInSeqNo = remoteInSeqNo;
    }

    /** {@return Whether the chat was created by us} */
    public boolean creator() {
        return creator;
    }

    /** {@return The number of messages received and processed so far} */
    public int inSeqNo() {
        return inSeqNo;
    }

    /** {@return The number of messages sent so far} */
    public int outSeqNo() {
        return outSeqNo;
    }

    /** {@return How many of our messages the peer has reported processing} */
    public int remoteInSeqNo() {
        return remoteInSeqNo;
    }

    /**
     * Computes the sequence numbers of the next outgoing message.
     *
     * <p> {@link Allocated#next()} must be persisted before the message is handed to
     * {@code messages.sendEncrypted*}: a message sent but not counted leaves the peer permanently
     * ahead of us.
     *
     * @return The values to put into the {@code decryptedMessageLayer}, and the counters that
     * follow sending it.
     */
    public Allocated allocate() {
        return new Allocated(2 * inSeqNo + inBase, 2 * outSeqNo + outBase,
                new SeqNoState(creator, inSeqNo, outSeqNo + 1, remoteInSeqNo));
    }

    /**
     * Classifies an incoming message.
     *
     * @param inSeqNo the {@code in_seq_no} of the received {@code decryptedMessageLayer}.
     * @param outSeqNo the {@code out_seq_no} of the received {@code decryptedMessageLayer}.
     * @throws SecretChatException if the values do not belong to the peer, or if the peer claims
     * to have processed messages we never sent, or fewer than it claimed before.
     * @return The classification, the raw sequence number, and the counters that follow.
     */
    public Incoming accept(int inSeqNo, int outSeqNo) {
        // The peer's counters are based the opposite way round from ours, so these are the
        // parities we do *not* use ourselves. Getting our own back would mean a reflected message
        if (inSeqNo < 0 || inSeqNo % 2 != outBase) {
            throw new SecretChatException("Unexpected in_seq_no: " + inSeqNo);
        }
        if (outSeqNo < 0 || outSeqNo % 2 != inBase) {
            throw new SecretChatException("Unexpected out_seq_no: " + outSeqNo);
        }

        int remoteIn = (inSeqNo - outBase) / 2;
        int seqNo = (outSeqNo - inBase) / 2;

        if (remoteIn < remoteInSeqNo) {
            throw new SecretChatException("in_seq_no is decreasing: "
                    + remoteIn + " < " + remoteInSeqNo);
        }
        // The peer may already count the message it is replying to, hence the one of slack
        if (remoteIn > this.outSeqNo + 1) {
            throw new SecretChatException("in_seq_no is bigger than the number of sent messages: "
                    + remoteIn + " > " + this.outSeqNo);
        }

        if (seqNo < this.inSeqNo) {
            return new Incoming(Status.REPEATED, seqNo,
                    new SeqNoState(creator, this.inSeqNo, this.outSeqNo, remoteIn));
        }
        if (seqNo > this.inSeqNo) {
            return new Incoming(Status.GAP, seqNo,
                    new SeqNoState(creator, this.inSeqNo, this.outSeqNo, remoteIn));
        }

        return new Incoming(Status.EXPECTED, seqNo,
                new SeqNoState(creator, this.inSeqNo + 1, this.outSeqNo, remoteIn));
    }

    /**
     * Converts a raw sequence number to the wire value the peer would have used for it.
     *
     * <p> Needed to fill {@code decryptedMessageActionResend}, whose bounds are expressed in the
     * numbering of the side being asked to resend.
     */
    public int toRemoteWireSeqNo(int seqNo) {
        return 2 * seqNo + inBase;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SeqNoState s)) return false;
        return creator == s.creator && inSeqNo == s.inSeqNo
                && outSeqNo == s.outSeqNo && remoteInSeqNo == s.remoteInSeqNo;
    }

    @Override
    public int hashCode() {
        int h = Boolean.hashCode(creator);
        h = h * 31 + inSeqNo;
        h = h * 31 + outSeqNo;
        h = h * 31 + remoteInSeqNo;
        return h;
    }

    @Override
    public String toString() {
        return "SeqNoState{in=" + inSeqNo + ", out=" + outSeqNo + ", remoteIn=" + remoteInSeqNo + '}';
    }
}
