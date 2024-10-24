package com.gstuer.casc.common.pattern;

import com.gstuer.casc.common.serialization.JsonProcessor;
import org.apache.commons.lang3.ArrayUtils;

import java.util.Objects;

public class EthernetPattern extends AccessRequestPattern {
    private final String source;
    private final String destination;
    private final String etherType;

    public EthernetPattern(String sourceAddress, String destinationAddress, String etherType) {
        this(sourceAddress, destinationAddress, etherType, null);
    }

    public EthernetPattern(String sourceAddress, String destinationAddress, String etherType, AccessRequestPattern enclosedPattern) {
        super(enclosedPattern);
        this.source = Objects.requireNonNull(sourceAddress);
        this.destination = Objects.requireNonNull(destinationAddress);
        this.etherType = Objects.requireNonNull(etherType);
    }

    public String getSource() {
        return this.source;
    }

    public String getDestination() {
        return this.destination;
    }

    public String getEtherType() {
        return this.etherType;
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
        EthernetPattern that = (EthernetPattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.etherType, that.etherType);
    }

    @Override
    public boolean equalsIsolated(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        EthernetPattern that = (EthernetPattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.etherType, that.etherType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), source, destination, etherType);
    }

    @Override
    public byte[] getSigningData() {
        byte[] bytes = source.concat(destination).concat(etherType).getBytes(JsonProcessor.getDefaultCharset());
        return ArrayUtils.addAll(bytes, super.getSigningData());
    }
}
