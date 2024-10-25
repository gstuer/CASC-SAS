package com.gstuer.casc.common.pattern;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.IpNumber;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.*;

public class IpPatternTest {
    @Test
    public void testContainsEqual() throws UnknownHostException {
        // Test data
        IpPattern firstPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);
        IpPattern secondPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);

        // Assertion
        assertTrue(firstPattern.contains(firstPattern));
        assertTrue(firstPattern.contains(secondPattern));
        assertTrue(secondPattern.contains(firstPattern));
        assertTrue(secondPattern.contains(secondPattern));
    }

    @Test
    public void testContainsUnequal() throws UnknownHostException {
        // Test data
        IpPattern firstPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);
        IpPattern secondPattern = new IpPattern(InetAddress.getByName("127.0.0.2"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);
        IpPattern thirdPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("254.255.255.255"), IpNumber.TCP);
        IpPattern fourthPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.UDP);

        // Assertion
        assertFalse(firstPattern.contains(secondPattern));
        assertFalse(firstPattern.contains(thirdPattern));
        assertFalse(firstPattern.contains(fourthPattern));

        assertFalse(secondPattern.contains(firstPattern));
        assertFalse(secondPattern.contains(thirdPattern));
        assertFalse(secondPattern.contains(fourthPattern));

        assertFalse(thirdPattern.contains(firstPattern));
        assertFalse(thirdPattern.contains(secondPattern));
        assertFalse(thirdPattern.contains(fourthPattern));

        assertFalse(fourthPattern.contains(firstPattern));
        assertFalse(fourthPattern.contains(secondPattern));
        assertFalse(fourthPattern.contains(thirdPattern));
    }

    @Test
    public void testContainsEqualEthernetEnclosed() throws UnknownHostException {
        // Test data
        EthernetPattern firstEthernet = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern firstIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, firstEthernet);
        EthernetPattern secondEthernet = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern secondIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, secondEthernet);

        // Assertion
        assertTrue(firstIP.contains(firstIP));
        assertTrue(firstIP.contains(secondIP));
        assertTrue(secondIP.contains(firstIP));
        assertTrue(secondIP.contains(secondIP));
    }


    @Test
    public void testContainsUnequalEthernetEnclosed() throws UnknownHostException {
        // Test data
        EthernetPattern firstEthernet = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern firstIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, firstEthernet);
        EthernetPattern secondEthernet = new EthernetPattern("ff:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern secondIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, secondEthernet);

        // Assertion
        assertFalse(firstIP.contains(secondIP));
        assertFalse(secondIP.contains(firstIP));
    }

    @Test
    public void testContainsEnclosedPattern() throws UnknownHostException {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);

        // Assertion
        assertTrue(ipPattern.contains(ethernetPattern));
        assertFalse(ethernetPattern.contains(ipPattern));
    }

    @Test
    public void testContainsEnclosedPatternTransitive() throws UnknownHostException {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern outerIpPattern = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, ethernetPattern);
        IpPattern innerIpPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, outerIpPattern);

        // Assertion
        assertTrue(innerIpPattern.contains(outerIpPattern));
        assertTrue(outerIpPattern.contains(ethernetPattern));
        assertTrue(innerIpPattern.contains(ethernetPattern));
    }

    @Test
    public void testContainsIsolatedEnclosedPattern() throws UnknownHostException {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern outerIpPattern = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, ethernetPattern);
        IpPattern innerIpPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, outerIpPattern);

        IpPattern outerIpPatternIsolated = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, null);

        // Assertion
        assertTrue(innerIpPattern.contains(outerIpPatternIsolated));
        assertTrue(outerIpPattern.contains(outerIpPatternIsolated));

        assertFalse(outerIpPatternIsolated.contains(innerIpPattern));
        assertFalse(outerIpPatternIsolated.contains(outerIpPattern));
    }

    @Test
    public void testContainsEnclosedPatternUnequalSubtree() throws UnknownHostException {
        // Test data
        EthernetPattern firstEthernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern outerIpPattern = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, firstEthernetPattern);
        IpPattern innerIpPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, outerIpPattern);

        EthernetPattern secondEthernetPattern = new EthernetPattern("ff:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IpPattern outerIpPatternDifferentSubtree = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, secondEthernetPattern);

        // Assertion
        assertNotEquals(firstEthernetPattern, secondEthernetPattern);
        assertFalse(innerIpPattern.contains(outerIpPatternDifferentSubtree));
        assertFalse(outerIpPattern.contains(outerIpPatternDifferentSubtree));
    }
}
