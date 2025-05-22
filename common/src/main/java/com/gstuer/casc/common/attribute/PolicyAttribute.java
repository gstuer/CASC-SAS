package com.gstuer.casc.common.attribute;

import com.google.common.primitives.Bytes;
import com.gstuer.casc.common.cryptography.Signable;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

public abstract class PolicyAttribute<T> implements Signable, Serializable {
    @Serial
    private static final long serialVersionUID = -8322128904857578281L;

    private final String identifier;
    private final Instant validFrom;
    private final Instant validUntil;
    private final T value;

    public PolicyAttribute(String identifier, Instant validFrom, Instant validUntil, T value) {
        this.identifier = Objects.requireNonNull(identifier);
        this.validFrom = Objects.requireNonNull(validFrom);
        this.validUntil = Objects.requireNonNull(validUntil);
        this.value = Objects.requireNonNull(value);
    }

    public String getIdentifier() {
        return identifier;
    }

    public Instant getValidFrom() {
        return validFrom;
    }

    public Instant getValidUntil() {
        return validUntil;
    }

    public T getValue() {
        return value;
    }

    public abstract byte[] getValueAsBytes();

    @Override
    public byte[] getSigningData() {
        byte[] identifierBytes = this.identifier.getBytes();
        return Bytes.concat(identifierBytes, this.getValueAsBytes());
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        PolicyAttribute<?> that = (PolicyAttribute<?>) object;
        return Objects.equals(identifier, that.identifier) && Objects.equals(validFrom, that.validFrom)
                && Objects.equals(validUntil, that.validUntil) && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier, validFrom, validUntil, value);
    }
}
