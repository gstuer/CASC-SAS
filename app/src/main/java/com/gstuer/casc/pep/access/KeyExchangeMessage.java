package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.access.cryptography.EncodedKey;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;

import java.io.Serial;
import java.net.InetAddress;

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
    public String toString() {
        try {
            return new JsonProcessor().convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
