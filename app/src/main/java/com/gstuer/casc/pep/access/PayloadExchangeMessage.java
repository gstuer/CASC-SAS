package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;
import org.pcap4j.packet.Packet;

import java.io.Serial;
import java.net.InetAddress;

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
    public String toString() {
        try {
            return new JsonProcessor().convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
