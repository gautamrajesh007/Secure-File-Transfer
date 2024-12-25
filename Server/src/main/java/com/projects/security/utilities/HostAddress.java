package com.projects.security.utilities;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

public class HostAddress {

    public HostAddress() {}

    public String getIPv4Address() throws SocketException {
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface netInter = networkInterfaces.nextElement();
            if (!netInter.isUp()) {
                continue;
            }
            if (netInter.isLoopback()) {
                continue;
            }
            Enumeration<InetAddress> addresses = netInter.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress address = addresses.nextElement();
                if (address.isLinkLocalAddress()) {
                    continue;
                }
                if (address.isSiteLocalAddress()) {
                    return address.getHostAddress();
                }
            }
        }
        return null;
    }

}
