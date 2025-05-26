package com.gstuer.casc.common.attribute;

import com.google.common.primitives.Bytes;
import com.gstuer.casc.common.cryptography.Signable;
import com.gstuer.casc.common.serialization.JsonProcessor;

import java.io.Serial;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.Objects;

public class AttributeIdentifier implements Serializable, Signable {
    @Serial
    private static final long serialVersionUID = 1955395573321510696L;

    private final String name;
    private final InetAddress provider;

    public AttributeIdentifier(String name, InetAddress provider) {
        this.name = name;
        this.provider = provider;
    }

    public String getName() {
        return name;
    }

    public InetAddress getProvider() {
        return provider;
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        AttributeIdentifier that = (AttributeIdentifier) object;
        return Objects.equals(this.name, that.name) && Objects.equals(this.provider, that.provider);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, provider);
    }

    @Override
    public byte[] getSigningData() {
        return Bytes.concat(this.name.getBytes(JsonProcessor.getDefaultCharset()), this.provider.getAddress());
    }
}
