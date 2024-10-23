package com.gstuer.casc.common.pattern;

import java.util.Objects;

public abstract class TransportProtocolPattern extends AccessRequestPattern {
    private final int sourcePort;
    private final int destinationPort;

    protected TransportProtocolPattern(int sourcePort, int destinationPort, AccessRequestPattern enclosedPattern) {
        super(enclosedPattern);
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        if (!super.equals(object)) {
            return false;
        }
        TransportProtocolPattern that = (TransportProtocolPattern) object;
        return sourcePort == that.sourcePort && destinationPort == that.destinationPort;
    }

    @Override
    public boolean equalsIsolated(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        TransportProtocolPattern that = (TransportProtocolPattern) object;
        return sourcePort == that.sourcePort && destinationPort == that.destinationPort;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), sourcePort, destinationPort);
    }
}
