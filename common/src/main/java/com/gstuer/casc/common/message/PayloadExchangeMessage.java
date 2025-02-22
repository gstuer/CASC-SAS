package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;
import org.pcap4j.packet.Packet;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;

public class PayloadExchangeMessage extends AccessControlMessage<Packet> {
    @Serial
    private static final long serialVersionUID = 5060347937847810073L;

    public PayloadExchangeMessage(InetAddress source, InetAddress destination, DigitalSignature signature, Packet packet) {
        super(source, destination, signature, packet);
    }

    public PayloadExchangeMessage(InetAddress destination, DigitalSignature signature, Packet packet) {
        super(destination, signature, packet);
    }

    @Override
    public PayloadExchangeMessage fromSource(InetAddress source) {
        return new PayloadExchangeMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public PayloadExchangeMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(this);
        return new PayloadExchangeMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
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
    public byte[] getSigningData() {
        return this.getPayload().getRawData();
    }

    @Override
    protected boolean hasEqualPayload(AccessControlMessage<?> message) {
        if (message == null || getClass() != message.getClass()) {
            return false;
        }
        PayloadExchangeMessage that = (PayloadExchangeMessage) message;
        return Objects.deepEquals(this.getPayload().getRawData(), that.getPayload().getRawData());
    }
}
