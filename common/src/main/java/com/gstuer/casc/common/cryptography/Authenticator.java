package com.gstuer.casc.common.cryptography;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

public abstract class Authenticator implements Signer, Verifier {
    private PrivateKey signingKey;
    private PublicKey verificationKey;

    @Override
    public PublicKey getVerificationKey() {
        return this.verificationKey;
    }

    @Override
    public void setVerificationKey(PublicKey verificationKey) {
        this.verificationKey = Objects.requireNonNull(verificationKey);
    }

    protected PrivateKey getSigningKey() {
        return this.signingKey;
    }

    @Override
    public void setSigningKey(PrivateKey signingKey) {
        this.signingKey = Objects.requireNonNull(signingKey);
    }
}
