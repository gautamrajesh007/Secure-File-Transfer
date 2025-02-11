package com.projects.security;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class SecureServer {
    @SuppressWarnings("InfiniteLoopStatement")
    public static void main(String[] args) {
        final int PORT = 12345;
        try {
            SSLServerSocketFactory sslSocketFactory = SecureSocket.getSSLServerSocketFactory();
            try(SSLServerSocket serverSocket = (SSLServerSocket) sslSocketFactory.createServerSocket(PORT)) {
                System.out.println("Secure server is running on port " + PORT);
                while (true) {
                    new Thread(new ClientHandler((SSLSocket) serverSocket.accept())).start();
                }
            }
        } catch (UnrecoverableKeyException | CertificateException | KeyStoreException | IOException |
                 NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }
}

