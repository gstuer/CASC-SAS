package com.gstuer.casc.common.attribute;

import com.google.common.primitives.Longs;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

public class LongAttribute extends PolicyAttribute<Long> {
    @Serial
    private static final long serialVersionUID = -2625075482404930676L;

    public LongAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, Long value) {
        super(identifier, validFrom, validityDuration, value);
    }

    public LongAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, Supplier<Long> valueSupplier) {
        super(identifier, validFrom, validityDuration, valueSupplier);
    }

    @Override
    public byte[] getValueAsBytes() {
        return Longs.toByteArray(this.getValue());
    }
}
