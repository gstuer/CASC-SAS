package com.gstuer.casc.common.pattern;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentSkipListSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AccessRequestPatternTest {
    @Test
    public void testNaturalOrdering() throws UnknownHostException {
        // Test data
        SortedSet<AccessRequestPattern> set = new ConcurrentSkipListSet<>();
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);
        AccessRequestPattern udpPattern = new UdpPattern(10000, 10001, ipPattern);

        // Execution
        set.add(ipPattern);
        set.add(ethernetPattern);
        set.add(udpPattern);

        // Assertions
        //// Most specific pattern first
        assertEquals(udpPattern, set.first());
        assertEquals(ethernetPattern, set.last());
    }
}
