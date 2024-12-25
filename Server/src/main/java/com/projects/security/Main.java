package com.projects.security;

import com.projects.security.utilities.HostAddress;
import java.net.SocketException;

public class Main {
    public static void main(String[] args) throws SocketException {
        String host = new HostAddress().getIPv4Address();
        Integer port = 443;
        System.out.println(host);
    }
}