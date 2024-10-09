package com.gstuer.casc.pep.access.cryptography;

import java.util.Arrays;
import java.util.Objects;

public class EncodedKey {
    private final String algorithmIdentifier;
    private final byte[] key;

    public EncodedKey(String algorithmIdentifier, byte[] key) {
        this.algorithmIdentifier = Objects.requireNonNull(algorithmIdentifier);
        this.key = Objects.requireNonNull(key);
    }

    public String getAlgorithmIdentifier() {
        return this.algorithmIdentifier;
    }

    public byte[] getKey() {
        return this.key;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        EncodedKey that = (EncodedKey) object;
        return Objects.equals(algorithmIdentifier, that.algorithmIdentifier) && Objects.deepEquals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithmIdentifier, Arrays.hashCode(key));
    }
}
