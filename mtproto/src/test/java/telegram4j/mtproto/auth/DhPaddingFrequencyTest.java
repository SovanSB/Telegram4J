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
package telegram4j.mtproto.auth;

import io.netty.buffer.ByteBuf;
import org.junit.jupiter.api.Test;
import telegram4j.mtproto.util.CryptoUtil;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Measures how often the authorization key was short before shared keys were padded to a fixed
 * width, which is the whole reason this branch exists. Not part of the test suite on any other
 * branch; it takes about ten seconds and asserts almost nothing.
 *
 * <p> The pre-fix expression, {@code toByteBuf(dh.computeSharedKey(..))}, is reproduced here
 * verbatim rather than by reverting the fix, so the branch stays rebaseable. A disagreement with
 * {@code computeSharedKeyData} is exactly the case where the handshake died with
 * "newNonceHash1 mismatch": the server derives {@code auth_key_id} from a full-width key and we
 * derive it from a truncated one.
 *
 * <p> Observed over three runs of 3000: 16, 22 and 19 failures, first at attempts 621, 221 and
 * 258. The rate is not 2^-8 as a first glance suggests, because the shared key is uniform over
 * {@code [0, dh_prime)} rather than over all 2048-bit numbers, and the prime begins with 0xc7:
 * {@code 2^2040 / dh_prime} is about 1 in 199. The observed 57 failures in 9000 attempts sit
 * 1.8 sigma above the 45.2 that predicts.
 */
class DhPaddingFrequencyTest {

    static final int ATTEMPTS = 3000;

    @Test
    void howOftenTheKeyWasShort() throws Exception {
        var dh = DhParametersTest.params();

        // one fixed peer public key: the shared key is still a fresh uniform group element per
        // attempt, and this halves the modular exponentiations
        BigInteger peerPublic = dh.computePublicKey(DhParameters.generateSecret());

        var failures = new ArrayList<String>();
        long started = System.nanoTime();

        for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
            BigInteger secret = DhParameters.generateSecret();
            BigInteger shared = dh.computeSharedKey(peerPublic, secret);

            ByteBuf legacy = CryptoUtil.toByteBuf(shared);
            int legacyLength = legacy.readableBytes();

            ByteBuf padded = dh.computeSharedKeyData(peerPublic, secret);
            long legacyId = new AuthKey(legacy).id();
            long paddedId = new AuthKey(padded).id();
            padded.release();

            if (legacyLength != DhParameters.KEY_SIZE || legacyId != paddedId) {
                failures.add(String.format("  attempt %4d: %d bytes (bitLength %d), auth_key_id 0x%016x vs 0x%016x",
                        attempt, legacyLength, shared.bitLength(), legacyId, paddedId));
            }
        }

        var probability = new BigDecimal(BigInteger.ONE.shiftLeft(2040))
                .divide(new BigDecimal(dh.prime()), MathContext.DECIMAL64);

        var report = new StringBuilder(String.format(
                "%d attempts in %.1fs%n  P(short key) = 2^2040 / dh_prime = 1 in %.1f%n" +
                "  expected %.2f failures, observed %d%n",
                ATTEMPTS, (System.nanoTime() - started) / 1e9,
                BigDecimal.ONE.divide(probability, MathContext.DECIMAL64),
                probability.doubleValue() * ATTEMPTS, failures.size()));
        failures.forEach(f -> report.append(f).append('\n'));

        Path out = Path.of("build", "dh-padding-frequency.txt");
        Files.createDirectories(out.getParent());
        Files.writeString(out, report);
        System.out.print(report);

        // the fix itself is what must hold: padding never changes a key that was already full width
        assertEquals(0, failures.stream()
                .filter(f -> f.contains(DhParameters.KEY_SIZE + " bytes"))
                .count(), "a full-width key must not depend on the padding");
    }
}
