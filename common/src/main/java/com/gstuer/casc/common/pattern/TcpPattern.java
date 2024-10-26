package com.gstuer.casc.common.pattern;

public class TcpPattern extends TransportProtocolPattern {
    public TcpPattern(int sourcePort, int destinationPort, AccessRequestPattern enclosedPattern) {
        super(sourcePort, destinationPort, enclosedPattern);
    }
}
