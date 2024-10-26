package com.gstuer.casc.common.pattern;

public class UdpPattern extends TransportProtocolPattern {
    public UdpPattern(int sourcePort, int destinationPort, AccessRequestPattern enclosedPattern) {
        super(sourcePort, destinationPort, enclosedPattern);
    }
}
