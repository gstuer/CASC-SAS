package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;
import org.pcap4j.packet.Packet;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

public class AccessRequest implements Serializable {
    @Serial
    private static final long serialVersionUID = 5060347937847810073L;

    private final DigitalSignature signature;
    private final Packet packet;

    public AccessRequest(DigitalSignature signature, Packet packet) {
        this.signature = Objects.requireNonNull(signature);
        this.packet = Objects.requireNonNull(packet);
    }

    public DigitalSignature getSignature() {
        return this.signature;
    }

    public Packet getPacket() {
        return this.packet;
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
