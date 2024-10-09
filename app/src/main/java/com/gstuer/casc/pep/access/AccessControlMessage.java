package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;

import java.io.Serial;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;

public abstract class AccessControlMessage<T> implements Serializable {
    @Serial
    private static final long serialVersionUID = 5060347937847810073L;

    private final String sourceAddress;
    private final String destinationAddress;
    private final DigitalSignature signature;
    private final T payload;

    protected AccessControlMessage(InetAddress source, InetAddress destination, DigitalSignature signature, T payload) {
        this.sourceAddress = Objects.isNull(source) ? null : source.getHostAddress();
        this.destinationAddress = destination.getHostAddress();
        this.signature = signature;
        this.payload = payload;
    }

    protected AccessControlMessage(InetAddress destination, DigitalSignature signature, T payload) {
        this(null, destination, signature, payload);
    }

    public InetAddress getSource() {
        if (Objects.isNull(this.sourceAddress)) {
            return null;
        }
        try {
            return InetAddress.getByName(destinationAddress);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public InetAddress getDestination() {
        try {
            return InetAddress.getByName(destinationAddress);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public DigitalSignature getSignature() {
        return this.signature;
    }

    public boolean hasSignature() {
        return Objects.nonNull(this.signature);
    }

    public T getPayload() {
        return this.payload;
    }

    public boolean hasPayload() {
        return Objects.nonNull(this.payload);
    }

    public abstract AccessControlMessage<T> fromSource(InetAddress source);

    @Override
    public String toString() {
        try {
            String json = new JsonProcessor(true).convertToJson(this);
            return "[" + this.getClass().getSimpleName() + "]" + json;
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
