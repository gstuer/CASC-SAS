package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;

import java.io.Serial;
import java.net.InetAddress;

public class KeyExchangeRequestMessage extends AccessControlMessage<String> {
    @Serial
    private static final long serialVersionUID = -6381850339226959873L;

    public KeyExchangeRequestMessage(InetAddress source, InetAddress destination, DigitalSignature signature, String algorithmIdentifier) {
        super(source, destination, signature, algorithmIdentifier);
    }

    public KeyExchangeRequestMessage(InetAddress destination, DigitalSignature signature, String algorithmIdentifier) {
        super(destination, signature, algorithmIdentifier);
    }

    @Override
    public KeyExchangeRequestMessage fromSource(InetAddress source) {
        return new KeyExchangeRequestMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public String toString() {
        try {
            return new JsonProcessor().convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
