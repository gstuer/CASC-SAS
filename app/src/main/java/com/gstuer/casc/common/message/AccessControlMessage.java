package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signable;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.cryptography.Verifier;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.io.Serial;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;

public abstract class AccessControlMessage<T> implements Serializable, Signable {
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
            return InetAddress.getByName(this.sourceAddress);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public InetAddress getDestination() {
        try {
            return InetAddress.getByName(this.destinationAddress);
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

    public abstract AccessControlMessage<T> sign(Signer signer) throws SignatureException, InvalidKeyException;

    public boolean verify(Verifier verifier) throws SignatureException, InvalidKeyException {
        return verifier.verify(this.getSigningData(), this.getSignature());
    }

    @Override
    public String toString() {
        try {
            String json = new JsonProcessor(true).convertToJson(this);
            return "[" + this.getClass().getSimpleName() + "]" + json;
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        AccessControlMessage<?> that = (AccessControlMessage<?>) object;
        return Objects.equals(sourceAddress, that.sourceAddress)
                && Objects.equals(destinationAddress, that.destinationAddress)
                && Objects.equals(signature, that.signature)
                && Objects.equals(payload, that.payload);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceAddress, destinationAddress, signature, payload);
    }
}
