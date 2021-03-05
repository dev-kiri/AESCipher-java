import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 *
 * AESCipher Library that helps you AES encryption
 * @author Kiri.dev
 */
public final class AESCipher {
    /**
     *
     * Turns Response {@link EncryptedBytes}
     * <p>
     * Use examples:
     * <ul>
     *   <li><code>AESCipher.encrypt("The quick brown fox jumps over the lazy dog 👻 👻", "René Über")</code></li>
     * </ul>
     * @param message Message to be encrypted
     * @param passphrase Secret passphrase to be used to encryption
     * @return EncryptedBytes
     * @see EncryptedBytes
     */
    public static EncryptedBytes encrypt(String message, String passphrase) {
        try {
            byte[] salted = new byte[0];
            byte[] dx = new byte[0];
            byte[] salt = new byte[8];

            new SecureRandom().nextBytes(salt);

            while (salted.length < 48) {
                dx = md5(addBytes(dx, passphrase.getBytes(), salt));
                salted = addBytes(salted, dx);
            }

            byte[] key = Arrays.copyOfRange(salted, 0, 32);
            byte[] iv = Arrays.copyOfRange(salted, 32, 48);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            byte[] finalIV = new byte[16];
            int len = Math.min(iv.length, 16);

            System.arraycopy(iv, 0, finalIV, 0, len);

            IvParameterSpec ivPS = new IvParameterSpec(finalIV);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivPS);
            byte[] bytes = cipher.doFinal(message.getBytes());
            byte[] saltedBytes = addBytes("Salted__".getBytes(), salt, bytes);

            return new EncryptedBytes(saltedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     *
     * Turns Response {@link DecryptedBytes}
     * <p>
     * Use examples:
     * <ul>
     *   <li><code>AESCipher.decrypt("U2FsdGVkX1+tsmZvCEFa/iGeSA0K7gvgs9KXeZKwbCDNCs2zPo+BXjvKYLrJutMK+hxTwl/hyaQLOaD7LLIRo2I5fyeRMPnroo6k8N9uwKk=", "René Über")</code></li>
     * </ul>
     * @param ciphertext Encrypted ciphertext to be decrypted
     * @param passphrase Secret passphrase to be used to decryption
     * @return DecryptedBytes
     * @see DecryptedBytes
     */
    public static DecryptedBytes decrypt(String ciphertext, String passphrase) {
        try {
            byte[] cipherData = Base64.getDecoder().decode(ciphertext);
            byte[] saltData = Arrays.copyOfRange(cipherData, 8, 16);

            MessageDigest md = MessageDigest.getInstance("MD5");

            final byte[][] keys = generateDecryptKey(saltData, passphrase.getBytes(), md);
            SecretKeySpec keySpec = new SecretKeySpec(keys[0], "AES");
            IvParameterSpec ivPS = new IvParameterSpec(keys[1]);

            byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivPS);

            byte[] decryptedData = cipher.doFinal(encrypted);
            return new DecryptedBytes(decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     *
     * Basic reference https://stackoverflow.com/questions/41432896/cryptojs-aes-encryption-and-java-aes-decryption
     */
    private static byte[][] generateDecryptKey(byte[] salt, byte[] password, MessageDigest md) {
        int digestLength = md.getDigestLength();
        int requiredLength = (48 + digestLength - 1) / digestLength * digestLength;
        byte[] generatedData = new byte[requiredLength];
        int generatedLength = 0;

        try {
            md.reset();

            while (generatedLength < 48) {

                if (generatedLength > 0) md.update(generatedData, generatedLength - digestLength, digestLength);
                md.update(password);

                if (salt != null) md.update(salt, 0, 8);
                md.digest(generatedData, generatedLength, digestLength);

                generatedLength += digestLength;
            }

            byte[][] result = new byte[2][];
            result[0] = Arrays.copyOfRange(generatedData, 0, 32);
            result[1] = Arrays.copyOfRange(generatedData, 32, 48);

            return result;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        finally {
            Arrays.fill(generatedData, (byte) 0);
        }
    }

    /**
     *
     * @param bytes ByteArray to be added
     * @return Added ByteArray
     */
    private static byte[] addBytes(byte[]... bytes) {
        int len = 0;
        for (byte[] b : bytes) len += b.length;

        byte[] r = new byte[len];
        int c = 0;
        for (byte[] b : bytes) {
            System.arraycopy(b, 0, r, c, b.length);
            c += b.length;
        }

        return r;
    }
    /**
     *
     * @param input Input to be hashed
     * @return hashed bytearray
     */
    private static byte[] md5(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(input);
            return md.digest();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static class EncryptedBytes {
        protected byte[] output;

        public EncryptedBytes(byte[] output) throws Exception {
            this.output = output;
        }

        @Override
        public String toString() {
            return toString("base64");
        }

        /**
         *
         * Turns to {@link String}
         * <p>
         * Use examples:
         * <ul>
         *   <li><code>AESCipher.encrypt(message, secret).toString("base64")</code></li>
         *   <li><code>AESCipher.encrypt(message, secret).toString("hex")</code></li>
         * </ul>
         * @param transformation transformation option
         * @return hex string or base64 string
         * @throws InvalidTransformationException when transformation is neither "hex" or "base64"
         */
        public String toString(String transformation) {
            switch (transformation) {
                case "hex" -> {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : output) sb.append(String.format("%02x", b & 0xFF));
                    return sb.toString();
                }
                case "base64" -> {
                    Base64.Encoder encoder = Base64.getEncoder();
                    return encoder.encodeToString(output);
                }
                default -> {
                    throw new InvalidTransformationException("Invalid toString transformation", transformation);
                }
            }
        }
    }

    public static class DecryptedBytes {
        protected byte[] output;

        public DecryptedBytes(byte[] output) {
            this.output = output;
        }

        @Override
        public String toString() {
            return new String(output);
        }

        /**
         *
         * Turns to {@link String}
         * <p>
         * Use examples:
         * <ul>
         *   <li><code>AESCipher.decrypt(message, secret).toString()</code></li>
         *   <li><code>AESCipher.decrypt(message, secret).toString("UTF-8")</code></li>
         * </ul>
         * @param charset transformation option
         * @return String
         * @throws UnsupportedEncodingException when it has given invalid charset
         */
        public String toString(String charset) throws UnsupportedEncodingException {
            return new String(output, charset);
        }
    }

    /**
     *
     * Exception thrown when the transformation is invalid.
     */
    public static class InvalidTransformationException extends IllegalArgumentException {
        private final String transformation;

        public InvalidTransformationException(String message, String transformation) {
            super(message);
            this.transformation = transformation;
        }

        public String getTransformation() {
            return transformation;
        }

        @Override
        public String toString() {
            return super.toString() + ". TRANSFORMATION=" + transformation;
        }
    }
}
