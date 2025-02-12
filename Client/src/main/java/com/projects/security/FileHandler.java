package com.projects.security;

import io.github.cdimascio.dotenv.Dotenv;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class FileHandler {
    private static final Dotenv env = Dotenv.load();
    private static final String KEYSTORE_PATH = System.getProperty("user.dir") + env.get("KEYSTORE_PATH");
    private static String filePath;

    public FileHandler(String filePath) {
        FileHandler.filePath = filePath;
    }

    @SuppressWarnings("DuplicatedCode")
    public void encryption(OutputStream output) throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {
        // Extract file name
        File file = new File(filePath);
        String fileName = file.getName();

        // Load server's RSA public key
        PublicKey publicKey = loadServerPublicKey();

        // Generate AES key for file encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt AES key using RSA
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Send encrypted AES key
        DataOutputStream dataOutput = new DataOutputStream(output);
        dataOutput.writeUTF(fileName); // Send file name
        dataOutput.writeInt(encryptedKey.length);
        dataOutput.write(encryptedKey);
        dataOutput.flush();
        System.out.println("Encrypted AES Key Length: " + encryptedKey.length);

        // Encrypt the file using AES
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

        try (FileInputStream fileIn = new FileInputStream(filePath);
             CipherOutputStream cipherOut = new CipherOutputStream(output, aesCipher)
        ) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fileIn.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, bytesRead);
            }
            cipherOut.flush();
        }
        System.out.println("Encrypted file sent securely.");
        dataOutput.close();
        System.out.println("Data output closed.");
    }

    private static PublicKey loadServerPublicKey() throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(KEYSTORE_PATH), "password".toCharArray());
        Certificate cert = keyStore.getCertificate("server_cert");
        return cert.getPublicKey();
    }
}
