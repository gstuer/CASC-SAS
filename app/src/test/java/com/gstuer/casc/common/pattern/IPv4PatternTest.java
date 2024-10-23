package com.gstuer.casc.common.pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class IPv4PatternTest {
    @Test
    public void testContainsEqual() {
        // Test data
        IPv4Pattern firstPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06");
        IPv4Pattern secondPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06");

        // Assertion
        assertTrue(firstPattern.contains(firstPattern));
        assertTrue(firstPattern.contains(secondPattern));
        assertTrue(secondPattern.contains(firstPattern));
        assertTrue(secondPattern.contains(secondPattern));
    }

    @Test
    public void testContainsUnequal() {
        // Test data
        IPv4Pattern firstPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06");
        IPv4Pattern secondPattern = new IPv4Pattern("127.0.0.2", "255.255.255.255", "0x06");
        IPv4Pattern thirdPattern = new IPv4Pattern("127.0.0.1", "254.255.255.255", "0x06");
        IPv4Pattern fourthPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x11");

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
    public void testContainsEqualEthernetEnclosed() {
        // Test data
        EthernetPattern firstEthernet = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern firstIP = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", firstEthernet);
        EthernetPattern secondEthernet = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern secondIP = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", secondEthernet);

        // Assertion
        assertTrue(firstIP.contains(firstIP));
        assertTrue(firstIP.contains(secondIP));
        assertTrue(secondIP.contains(firstIP));
        assertTrue(secondIP.contains(secondIP));
    }


    @Test
    public void testContainsUnequalEthernetEnclosed() {
        // Test data
        EthernetPattern firstEthernet = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern firstIP = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", firstEthernet);
        EthernetPattern secondEthernet = new EthernetPattern("ff:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern secondIP = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", secondEthernet);

        // Assertion
        assertFalse(firstIP.contains(secondIP));
        assertFalse(secondIP.contains(firstIP));
    }

    @Test
    public void testContainsEnclosedPattern() {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern ipPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", ethernetPattern);

        // Assertion
        assertTrue(ipPattern.contains(ethernetPattern));
        assertFalse(ethernetPattern.contains(ipPattern));
    }

    @Test
    public void testContainsEnclosedPatternTransitive() {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern outerIpPattern = new IPv4Pattern("192.168.0.1", "192.168.0.2", "0x04", ethernetPattern);
        IPv4Pattern innerIpPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", outerIpPattern);

        // Assertion
        assertTrue(innerIpPattern.contains(outerIpPattern));
        assertTrue(outerIpPattern.contains(ethernetPattern));
        assertTrue(innerIpPattern.contains(ethernetPattern));
    }

    @Test
    public void testContainsIsolatedEnclosedPattern() {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern outerIpPattern = new IPv4Pattern("192.168.0.1", "192.168.0.2", "0x04", ethernetPattern);
        IPv4Pattern innerIpPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", outerIpPattern);

        IPv4Pattern outerIpPatternIsolated = new IPv4Pattern("192.168.0.1", "192.168.0.2", "0x04", null);

        // Assertion
        assertTrue(innerIpPattern.contains(outerIpPatternIsolated));
        assertTrue(outerIpPattern.contains(outerIpPatternIsolated));

        assertFalse(outerIpPatternIsolated.contains(innerIpPattern));
        assertFalse(outerIpPatternIsolated.contains(outerIpPattern));
    }

    @Test
    public void testContainsEnclosedPatternUnequalSubtree() {
        // Test data
        EthernetPattern firstEthernetPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern outerIpPattern = new IPv4Pattern("192.168.0.1", "192.168.0.2", "0x04", firstEthernetPattern);
        IPv4Pattern innerIpPattern = new IPv4Pattern("127.0.0.1", "255.255.255.255", "0x06", outerIpPattern);

        EthernetPattern secondEthernetPattern = new EthernetPattern("ff:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        IPv4Pattern outerIpPatternDifferentSubtree = new IPv4Pattern("192.168.0.1", "192.168.0.2", "0x04", secondEthernetPattern);

        // Assertion
        assertNotEquals(firstEthernetPattern, secondEthernetPattern);
        assertFalse(innerIpPattern.contains(outerIpPatternDifferentSubtree));
        assertFalse(outerIpPattern.contains(outerIpPatternDifferentSubtree));
    }
}
