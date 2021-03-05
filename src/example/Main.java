package com.kiri.example;

import com.kiri.library.AESCipher;
import static com.kiri.library.AESCipher.EncryptedBytes;
import static com.kiri.library.AESCipher.DecryptedBytes;

public class Main {
    public static void main(String[] args) {
        String secret = "René Über";
        String message = "The quick brown fox jumps over the lazy dog. 👻 👻";
        EncryptedBytes encrypted = AESCipher.encrypt(message, secret);
        if (encrypted != null) {
            System.out.println("Base64 Encrypted result: " + encrypted.toString("base64"));
            System.out.println("Hex Encrypted result: " + encrypted.toString("hex"));
            DecryptedBytes decrypted = AESCipher.decrypt(encrypted.toString(), secret);
            System.out.println("Decrypted String result: " + decrypted);
        }
    }
}
