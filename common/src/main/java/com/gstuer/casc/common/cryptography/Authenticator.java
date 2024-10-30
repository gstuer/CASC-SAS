package com.gstuer.casc.common.cryptography;

import java.security.Key;
import java.util.Objects;

public abstract class Authenticator<S extends Key, V extends Key> implements Signer<S>, Verifier<V> {
    private S signingKey;
    private V verificationKey;

    @Override
    public V getVerificationKey() {
        return this.verificationKey;
    }

    @Override
    public void setVerificationKey(V verificationKey) {
        this.verificationKey = Objects.requireNonNull(verificationKey);
    }

    public abstract void initializeKeyPair();

    protected S getSigningKey() {
        return this.signingKey;
    }

    @Override
    public void setSigningKey(S signingKey) {
        this.signingKey = Objects.requireNonNull(signingKey);
    }
}
