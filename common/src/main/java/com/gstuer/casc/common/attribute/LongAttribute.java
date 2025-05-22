package com.gstuer.casc.common.attribute;

import com.google.common.primitives.Longs;

import java.io.Serial;
import java.time.Instant;

public class LongAttribute extends PolicyAttribute<Long> {
    @Serial
    private static final long serialVersionUID = -2625075482404930676L;

    public LongAttribute(String identifier, Instant validFrom, Instant validUntil, Long value) {
        super(identifier, validFrom, validUntil, value);
    }

    @Override
    public byte[] getValueAsBytes() {
        return Longs.toByteArray(this.getValue());
    }
}
