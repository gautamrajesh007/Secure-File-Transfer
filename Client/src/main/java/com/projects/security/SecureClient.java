package com.projects.security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class SecureClient {
    public static void main(String[] args) {
        final int port = 12345;
        String filePath;
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter the absolute path of the file to send: ");
        filePath = sc.nextLine();

        try {
            SSLSocketFactory socketFactory = SecureSocket.getSSLSocketFactory();
            try(SSLSocket clientSocket = (SSLSocket) socketFactory.createSocket("localhost", port);
                OutputStream output = clientSocket.getOutputStream()
            ) {
                clientSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                System.out.println("Connected to secure server.");
                FileHandler fileHandler = new FileHandler(filePath);
                fileHandler.encryption(output);
            }
        } catch (UnrecoverableKeyException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException |
                 CertificateException | KeyStoreException | IOException |
                 NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }

    }
}