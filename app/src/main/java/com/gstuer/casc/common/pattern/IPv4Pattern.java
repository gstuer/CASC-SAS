package com.gstuer.casc.common.pattern;

import java.util.Objects;

public class IPv4Pattern extends AccessRequestPattern {
    private final String source;
    private final String destination;
    private final String protocol;

    public IPv4Pattern(String source, String destination, String protocol) {
        this(source, destination, protocol, null);
    }

    public IPv4Pattern(String source, String destination, String protocol, AccessRequestPattern enclosedPattern) {
        super(enclosedPattern);
        this.source = source;
        this.destination = destination;
        this.protocol = protocol;
    }

    public String getSource() {
        return this.source;
    }

    public String getDestination() {
        return this.destination;
    }

    public String getProtocol() {
        return this.protocol;
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
        IPv4Pattern that = (IPv4Pattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.protocol, that.protocol);
    }

    @Override
    public boolean equalsIsolated(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        IPv4Pattern that = (IPv4Pattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.protocol, that.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), source, destination, protocol);
    }
}
