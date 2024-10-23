package com.gstuer.casc.common.pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EthernetPatternTest {
    @Test
    public void testContainsNoEnclosing() {
        // Test data
        EthernetPattern firstPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        EthernetPattern secondPattern = new EthernetPattern("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");
        EthernetPattern thirdPattern = new EthernetPattern("ff:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "0x0800");

        // Assertion
        assertTrue(firstPattern.contains(firstPattern));
        assertTrue(firstPattern.contains(secondPattern));
        assertTrue(secondPattern.contains(firstPattern));
        assertTrue(secondPattern.contains(secondPattern));

        assertFalse(firstPattern.contains(thirdPattern));
        assertFalse(thirdPattern.contains(firstPattern));
    }
}
