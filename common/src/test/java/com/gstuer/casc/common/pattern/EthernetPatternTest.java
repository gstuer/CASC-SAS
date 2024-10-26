package com.gstuer.casc.common.pattern;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EthernetPatternTest {
    @Test
    public void testContainsNoEnclosing() {
        // Test data
        EthernetPattern firstPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        EthernetPattern secondPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        EthernetPattern thirdPattern = new EthernetPattern(MacAddress.getByName("ff:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);

        // Assertion
        assertTrue(firstPattern.contains(firstPattern));
        assertTrue(firstPattern.contains(secondPattern));
        assertTrue(secondPattern.contains(firstPattern));
        assertTrue(secondPattern.contains(secondPattern));

        assertFalse(firstPattern.contains(thirdPattern));
        assertFalse(thirdPattern.contains(firstPattern));
    }
}
