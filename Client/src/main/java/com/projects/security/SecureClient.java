package com.projects.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;

public class SecureClient {
    public static void main(String[] args) {
        // Register BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        String host = "localhost";
        int port = 12345;

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("/Users/gautam/Security/Projects/TLS_Sim/Client/src/main/java/com/projects/security/keystores/client.jks"), "password".toCharArray());

            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(host, port);

            System.out.println("Connected to secure server.");

            try (
                    OutputStream output = socket.getOutputStream();
                    InputStream input = socket.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(input));
                    PrintWriter writer = new PrintWriter(output, true)
            ) {
                writer.println("FILE_TRANSFER");
                sendEncryptedFile(output);
//                System.out.println(reader.readLine());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendEncryptedFile(OutputStream output) throws Exception {
        // Generate AES key
        SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();

        // Encrypt AES key with server's public EC key
        PublicKey serverPublicKey = loadServerPublicKey();

        // Set up IES Parameters
        byte[] derivation = "DerivationKey".getBytes(); // Example derivation
        byte[] encoding = "EncodingKey".getBytes();    // Example encoding
        IESParameterSpec iesParams = new IESParameterSpec(derivation, encoding, 128);

        Cipher eciesCipher = Cipher.getInstance("ECIES", "BC");
        eciesCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey, iesParams);
        byte[] encryptedKey = eciesCipher.doFinal(aesKey.getEncoded());

        // Send encrypted AES key
        DataOutputStream dataOutput = new DataOutputStream(output);
        dataOutput.writeInt(encryptedKey.length);
        dataOutput.write(encryptedKey);
        dataOutput.flush();
        System.out.println("Encrypted AES Key Length: " + encryptedKey.length);

        // Encrypt file data with AES
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

        try (FileInputStream fileInput = new FileInputStream("/Users/gautam/Security/Projects/TLS_Sim/Client/src/main" +
                "/resources/Phishing_Detection_Dataset.csv");
             CipherOutputStream cipherOutput = new CipherOutputStream(output, aesCipher)) {

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fileInput.read(buffer)) != -1) {
                cipherOutput.write(buffer, 0, bytesRead);
            }
            cipherOutput.flush();
        }
        System.out.println("Encrypted file sent securely.");
    }

    private static PublicKey loadServerPublicKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("/Users/gautam/Security/Projects/TLS_Sim/Client/src/main/java/com/projects/security/keystores/server.jks"), "password".toCharArray());
        Certificate cert = keyStore.getCertificate("server");
        return cert.getPublicKey();
    }
}