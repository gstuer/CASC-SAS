package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;
import org.apache.commons.lang3.ArrayUtils;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class KeyExchangeMessage extends AccessControlMessage<EncodedKey> {
    @Serial
    private static final long serialVersionUID = -1138137919785740628L;

    public KeyExchangeMessage(InetAddress source, InetAddress destination, DigitalSignature signature, EncodedKey encodedKey) {
        super(source, destination, signature, encodedKey);
    }

    public KeyExchangeMessage(InetAddress destination, DigitalSignature signature, EncodedKey encodedKey) {
        super(destination, signature, encodedKey);
    }

    @Override
    public KeyExchangeMessage fromSource(InetAddress source) {
        return new KeyExchangeMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public KeyExchangeMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new KeyExchangeMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
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
        EncodedKey encodedKey = this.getPayload();
        return ArrayUtils.addAll(encodedKey.getAlgorithmIdentifier().getBytes(JsonProcessor.getDefaultCharset()),
                encodedKey.getKey());
    }
}
