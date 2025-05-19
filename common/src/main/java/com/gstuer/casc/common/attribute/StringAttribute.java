package com.gstuer.casc.common.attribute;

import java.time.Instant;

public class StringAttribute extends PolicyAttribute<String> {
    public StringAttribute(String identifier, Instant validFrom, Instant validUntil, String value) {
        super(identifier, validFrom, validUntil, value);
    }

    @Override
    public byte[] getValueAsBytes() {
        return this.getValue().getBytes();
    }
}
