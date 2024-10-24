package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;

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
    public KeyExchangeRequestMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new KeyExchangeRequestMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public String toString() {
        try {
            return new JsonProcessor().convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    protected byte[] getSigningData() {
        return this.getPayload().getBytes(JsonProcessor.getDefaultCharset());
    }
}
