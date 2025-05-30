package com.gstuer.casc.common.attribute;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

public class StringAttribute extends PolicyAttribute<String> {
    @Serial
    private static final long serialVersionUID = 132124938264322981L;

    public StringAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, String value) {
        super(identifier, validFrom, validityDuration, value);
    }

    public StringAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, Supplier<String> valueSupplier) {
        super(identifier, validFrom, validityDuration, valueSupplier);
    }

    @Override
    public byte[] getValueAsBytes() {
        return this.getValue().getBytes();
    }
}
