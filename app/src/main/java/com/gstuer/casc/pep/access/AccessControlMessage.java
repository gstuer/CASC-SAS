package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

public abstract class AccessControlMessage<T> implements Serializable {
    @Serial
    private static final long serialVersionUID = 5060347937847810073L;

    private final DigitalSignature signature;
    private final T payload;

    protected AccessControlMessage(DigitalSignature signature, T payload) {
        this.signature = Objects.requireNonNull(signature);
        this.payload = payload;
    }

    public DigitalSignature getSignature() {
        return this.signature;
    }

    public T getPayload() {
        return this.payload;
    }

    @Override
    public String toString() {
        try {
            return new JsonProcessor(true).convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
