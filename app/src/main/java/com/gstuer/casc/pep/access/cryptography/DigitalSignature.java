package com.gstuer.casc.pep.access.cryptography;

import java.io.Serial;
import java.io.Serializable;
import java.util.HexFormat;
import java.util.Objects;

public class DigitalSignature implements Serializable {
    @Serial
    private static final long serialVersionUID = -4856753793946331233L;

    private final byte[] data;
    private final String algorithmIdentifier;

    public <T extends Signer> DigitalSignature(byte[] data, String algorithmIdentifier) {
        this.data = Objects.requireNonNull(data);
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public byte[] getData() {
        return this.data;
    }

    public String getDataAsHex() {
        return HexFormat.of().formatHex(this.data);
    }

    public String getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public String toString() {
        return this.getDataAsHex();
    }
}
