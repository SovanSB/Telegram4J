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

import org.junit.jupiter.api.Test;
import telegram4j.mtproto.secret.SeqNoState.Status;
import telegram4j.mtproto.secret.SeqNoState.WireSeqNo;

import static org.junit.jupiter.api.Assertions.*;

class SeqNoStateTest {

    @Test
    void creatorParity() {
        // https://core.telegram.org/api/end-to-end/seq_no: the initiator sends odd out_seq_no
        // and even in_seq_no, the other participant the other way round
        assertEquals(new WireSeqNo(0, 1), new SeqNoState(true).allocate());
        assertEquals(new WireSeqNo(1, 0), new SeqNoState(false).allocate());
    }

    @Test
    void countersAdvanceIndependently() {
        var creator = new SeqNoState(true);

        assertEquals(new WireSeqNo(0, 1), creator.allocate());
        assertEquals(new WireSeqNo(0, 3), creator.allocate());

        // receiving advances only the incoming counter
        assertEquals(new SeqNoState.Incoming(Status.EXPECTED, 0), creator.accept(1, 0));
        assertEquals(1, creator.inSeqNo());
        assertEquals(2, creator.outSeqNo());

        assertEquals(new WireSeqNo(2, 5), creator.allocate());
    }

    @Test
    void twoSidesStayInStep() {
        var creator = new SeqNoState(true);
        var participant = new SeqNoState(false);

        for (int i = 0; i < 16; i++) {
            var sent = creator.allocate();
            assertEquals(new SeqNoState.Incoming(Status.EXPECTED, i), participant.accept(sent.inSeqNo(), sent.outSeqNo()));

            var reply = participant.allocate();
            assertEquals(new SeqNoState.Incoming(Status.EXPECTED, i), creator.accept(reply.inSeqNo(), reply.outSeqNo()));
        }

        assertEquals(16, creator.inSeqNo());
        assertEquals(16, creator.outSeqNo());
        assertEquals(16, creator.remoteInSeqNo());
    }

    @Test
    void outgoingCounterIgnoresWhatThePeerReports() {
        // the regression this class exists for: a peer that replies before counting the message
        // it is replying to reports one less than we have sent, and adopting that value would
        // make the next message reuse a sequence number
        var creator = new SeqNoState(true);
        creator.allocate();
        creator.allocate();
        creator.allocate();

        // the participant answers acknowledging only one of our three messages
        var lagging = new SeqNoState(false);
        lagging.accept(0, 1);
        var reply = lagging.allocate();
        assertEquals(new WireSeqNo(3, 0), reply);

        assertEquals(new SeqNoState.Incoming(Status.EXPECTED, 0), creator.accept(reply.inSeqNo(), reply.outSeqNo()));
        assertEquals(1, creator.remoteInSeqNo());
        assertEquals(3, creator.outSeqNo(), "outgoing counter must not follow the peer");
        assertEquals(new WireSeqNo(2, 7), creator.allocate());
    }

    @Test
    void detectsRepeatsAndGaps() {
        var participant = new SeqNoState(false);

        assertEquals(Status.EXPECTED, participant.accept(0, 1).status());
        assertEquals(Status.REPEATED, participant.accept(0, 1).status());

        // the creator's third message arrives before its second
        var gap = participant.accept(0, 5);
        assertEquals(Status.GAP, gap.status());
        assertEquals(2, gap.seqNo());
        assertEquals(1, participant.inSeqNo(), "a gap must not advance the counter");

        assertEquals(Status.EXPECTED, participant.accept(0, 3).status());
        assertEquals(Status.EXPECTED, participant.accept(0, 5).status());
    }

    @Test
    void rejectsOurOwnParity() {
        var creator = new SeqNoState(true);
        var mirrored = creator.allocate();

        // our own message handed back to us has both parities the wrong way round
        var e = assertThrowsExactly(SecretChatException.class,
                () -> creator.accept(mirrored.inSeqNo(), mirrored.outSeqNo()));
        assertTrue(e.getMessage().startsWith("Unexpected in_seq_no"), e.getMessage());
    }

    @Test
    void rejectsImpossibleAcknowledgements() {
        var creator = new SeqNoState(true);
        creator.allocate();

        // the peer claims to have processed messages we never sent
        assertThrowsExactly(SecretChatException.class, () -> creator.accept(7, 0));

        // ...and one of slack is allowed, for a peer that counts the message it is replying to
        assertEquals(Status.EXPECTED, creator.accept(5, 0).status());

        // going backwards afterwards is a protocol violation
        var e = assertThrowsExactly(SecretChatException.class, () -> creator.accept(1, 2));
        assertTrue(e.getMessage().startsWith("in_seq_no is decreasing"), e.getMessage());
    }

    @Test
    void resendBoundsUseThePeerNumbering() {
        var creator = new SeqNoState(true);
        var participant = new SeqNoState(false);

        // asking the participant to resend its messages 0..2 must name them the way it numbers
        // its own out_seq_no, which is the parity the creator reads them with
        assertEquals(0, creator.toRemoteWireSeqNo(0));
        assertEquals(4, creator.toRemoteWireSeqNo(2));

        participant.allocate();
        participant.allocate();
        var third = participant.allocate();
        assertEquals(creator.toRemoteWireSeqNo(2), third.outSeqNo());
    }

    @Test
    void restoresPersistedCounters() {
        var restored = new SeqNoState(true, 7, 9, 6);

        assertEquals(new WireSeqNo(14, 19), restored.allocate());
        assertEquals(Status.EXPECTED, restored.accept(13, 14).status());
        assertEquals(8, restored.inSeqNo());
        assertEquals(10, restored.outSeqNo());
        assertEquals(6, restored.remoteInSeqNo());
    }
}
