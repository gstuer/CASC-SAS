package com.gstuer.casc.common.attribute;

import java.io.Serial;
import java.time.Instant;

public class StringAttribute extends PolicyAttribute<String> {
    @Serial
    private static final long serialVersionUID = 132124938264322981L;

    public StringAttribute(String identifier, Instant validFrom, Instant validUntil, String value) {
        super(identifier, validFrom, validUntil, value);
    }

    @Override
    public byte[] getValueAsBytes() {
        return this.getValue().getBytes();
    }
}
