package com.projects.security.handlers;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;

public class ReceiveEncryptedFile {
    private final InputStream input;
    private final PrintWriter writer;

    public ReceiveEncryptedFile(InputStream input, PrintWriter writer) {
        this.input = input;
        this.writer = writer;
    }

    private PrivateKey loadPrivateKey() throws Exception {
        // Load server's private key from file
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("../../../server.jks"), "password".toCharArray());
        return (PrivateKey) keyStore.getKey("server", "password".toCharArray());
    }

    public void receiveEncryptedFile() throws Exception {
        // Read encrypted AES key
        byte[] encryptedKey = new byte[256]; // 256 is the typical size for ECDSA-encrypted data
        input.read(encryptedKey);

        // Decrypt AES key using server's private ECDSA key
        PrivateKey privateKey =  loadPrivateKey();
        Cipher ecdsaCipher = Cipher.getInstance("ECIES");
        ecdsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = ecdsaCipher.doFinal(encryptedKey);

        // Decrypted AES key is stored into a SecretKey object to used to file decryption.
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Decrypt file data
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

        File file = new File("received_encrypted_file.txt");
        try (FileOutputStream fileOut = new FileOutputStream(file);
             CipherInputStream cipherInput = new CipherInputStream(input, aesCipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cipherInput.read(buffer)) != -1) {
                fileOut.write(buffer, 0, bytesRead);
            }
        }

        writer.println("Encrypted file received securely.");
    }
}
