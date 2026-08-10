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
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import telegram4j.mtproto.auth.AuthKey;
import telegram4j.mtproto.util.AES256IGECipher;
import telegram4j.tl.SecretTlDeserializer;
import telegram4j.tl.SecretTlSerializer;
import telegram4j.tl.api.SecretObject;

import static telegram4j.mtproto.internal.Crypto.sha256Digest;
import static telegram4j.mtproto.util.CryptoUtil.random;

/**
 * Encryption of the {@code messages.sendEncrypted*} payloads with MTProto 2.0.
 *
 * <p> This is the same construction as {@code MTProtoEncryption} uses for the transport,
 * with two differences: the key is the one negotiated for the secret chat rather than the
 * authorization key, and the {@code x} offset of the key derivation is chosen by which side
 * created the chat instead of by the direction of the packet.
 *
 * <p> MTProto 1.0, which used SHA-1 and is what secret chats looked like before layer 73,
 * is not implemented in either direction.
 *
 * @implNote Instances are stateful and not thread safe, exactly like {@link AES256IGECipher}.
 * @see <a href="https://core.telegram.org/api/end-to-end">End-to-End Encryption, Secret Chats</a>
 */
public final class SecretChatCipher {
    /** Size of the key fingerprint and the message key which prefix every payload. */
    private static final int HEADER_SIZE = 8 + 16;
    private static final int MIN_PADDING = 12;
    private static final int MAX_PADDING = 1024;

    // Padding is not merely an alignment: rounding the encrypted size up to one of these
    // buckets is what hides the exact length of short messages. Taken from TDLib's
    // do_calc_crypto_size2_basic() so that our packets are indistinguishable from its own
    private static final int[] PADDING_BUCKETS = {64, 128, 192, 256, 384, 512, 768, 1024, 1280};
    private static final int PADDING_STEP = 448;

    private final AES256IGECipher cipher = AES256IGECipher.create();

    /**
     * Encrypts the given object into the payload of a {@code messages.sendEncrypted*} request.
     *
     * @param key the key negotiated for the secret chat.
     * @param creator whether the chat was created by us, i.e. whether we are its {@code admin_id}.
     * @param object the object to encrypt, normally a {@code DecryptedMessageLayer}.
     * @return The payload, which the caller owns.
     */
    public ByteBuf encrypt(AuthKey key, boolean creator, SecretObject object) {
        ByteBufAllocator alloc = ByteBufAllocator.DEFAULT;

        int objectSize = SecretTlSerializer.sizeOf(object);
        int dataSize = Integer.BYTES + objectSize;
        int paddedSize = paddedSize(dataSize);
        int paddingSize = paddedSize - dataSize;

        byte[] paddingBytes = new byte[paddingSize];
        random.nextBytes(paddingBytes);

        ByteBuf plainText = alloc.buffer(paddedSize);
        plainText.writeIntLE(objectSize);
        SecretTlSerializer.serialize(plainText, object);
        plainText.writeBytes(paddingBytes);

        int x = creator ? 0 : 8;
        ByteBuf messageKey = computeMessageKey(key, x, plainText);

        initCipher(true, key, messageKey, x);
        ByteBuf encrypted = cipher.encrypt(plainText);

        ByteBuf payload = alloc.buffer(HEADER_SIZE + encrypted.readableBytes());
        payload.writeLongLE(key.id());
        payload.writeBytes(messageKey);
        payload.writeBytes(encrypted);

        messageKey.release();
        encrypted.release();

        return payload;
    }

    /**
     * Decrypts the payload of an {@code encryptedMessage} received in the chat.
     *
     * @param key the key negotiated for the secret chat.
     * @param creator whether the chat was created by us, i.e. whether we are its {@code admin_id}.
     * @param payload the {@code bytes} of the received message; not released by this method.
     * @throws SecretChatException if the payload is malformed or its message key does not match.
     * @return The decrypted object, normally a {@code DecryptedMessageLayer}.
     */
    public SecretObject decrypt(AuthKey key, boolean creator, ByteBuf payload) {
        if (payload.readableBytes() < HEADER_SIZE + 16) {
            throw new SecretChatException("Payload is too small: " + payload.readableBytes());
        }

        long fingerprint = payload.getLongLE(payload.readerIndex());
        if (fingerprint != key.id()) {
            throw new SecretChatException("Key fingerprint mismatch, found: 0x" + Long.toHexString(fingerprint)
                    + ", expected: 0x" + Long.toHexString(key.id()));
        }

        ByteBuf messageKey = payload.slice(payload.readerIndex() + 8, 16);
        ByteBuf body = payload.slice(payload.readerIndex() + HEADER_SIZE,
                (payload.readableBytes() - HEADER_SIZE) & ~15);
        if (!body.isReadable()) {
            throw new SecretChatException("Payload has no encrypted part");
        }

        // Unlike outgoing messages, the offset here is the one of the *other* side
        int x = creator ? 8 : 0;

        initCipher(false, key, messageKey, x);
        ByteBuf decrypted = cipher.decrypt(body.retain());

        try {
            ByteBuf expectedMessageKey = computeMessageKey(key, x, decrypted);
            boolean matches = equalsConstantTime(messageKey, expectedMessageKey);
            expectedMessageKey.release();
            if (!matches) {
                throw new SecretChatException("Message key mismatch");
            }

            int objectSize = decrypted.readIntLE();
            int tailSize = decrypted.readableBytes();
            if (objectSize < 0 || objectSize % 4 != 0) {
                throw new SecretChatException("Invalid object length: " + objectSize);
            }
            if (objectSize > tailSize) {
                throw new SecretChatException("Object length is bigger than the payload: "
                        + objectSize + " > " + tailSize);
            }

            int paddingSize = tailSize - objectSize;
            if (paddingSize < MIN_PADDING || paddingSize > MAX_PADDING) {
                throw new SecretChatException("Invalid padding length: " + paddingSize);
            }

            return SecretTlDeserializer.deserialize(decrypted.slice(decrypted.readerIndex(), objectSize));
        } finally {
            decrypted.release();
        }
    }

    // msg_key_large = SHA256(substr(key, 88 + x, 32) + plaintext); msg_key = substr(msg_key_large, 8, 16)
    private static ByteBuf computeMessageKey(AuthKey key, int x, ByteBuf plainText) {
        ByteBuf large = sha256Digest(key.value().slice(88 + x, 32), plainText);
        ByteBuf messageKey = Unpooled.copiedBuffer(large.slice(8, 16));
        large.release();
        return messageKey;
    }

    private void initCipher(boolean encrypt, AuthKey key, ByteBuf messageKey, int x) {
        ByteBuf value = key.value();

        ByteBuf sha256a = sha256Digest(messageKey, value.slice(x, 36));
        ByteBuf sha256b = sha256Digest(value.slice(40 + x, 36), messageKey);

        ByteBuf aesKey = Unpooled.wrappedBuffer(
                sha256a.retainedSlice(0, 8),
                sha256b.retainedSlice(8, 16),
                sha256a.retainedSlice(24, 8));

        ByteBuf aesIV = Unpooled.wrappedBuffer(
                sha256b.retainedSlice(0, 8),
                sha256a.retainedSlice(8, 16),
                sha256b.retainedSlice(24, 8));
        sha256a.release();
        sha256b.release();

        // init() releases aesKey, and the iv is released by the following encrypt()/decrypt()
        cipher.init(encrypt, aesKey, aesIV);
    }

    static int paddedSize(int dataSize) {
        int size = dataSize + MIN_PADDING + 15 & ~15;
        for (int bucket : PADDING_BUCKETS) {
            if (size <= bucket) {
                return bucket;
            }
        }
        return (size - PADDING_BUCKETS[PADDING_BUCKETS.length - 1] + PADDING_STEP - 1)
                / PADDING_STEP * PADDING_STEP + PADDING_BUCKETS[PADDING_BUCKETS.length - 1];
    }

    private static boolean equalsConstantTime(ByteBuf left, ByteBuf right) {
        int diff = left.readableBytes() ^ right.readableBytes();
        for (int i = 0, n = Math.min(left.readableBytes(), right.readableBytes()); i < n; i++) {
            diff |= left.getByte(left.readerIndex() + i) ^ right.getByte(right.readerIndex() + i);
        }
        return diff == 0;
    }
}
