package com.gstuer.casc.pep.access.cryptography;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SignatureException;

public interface Signer {
    public DigitalSignature sign(byte[] data) throws InvalidKeyException, SignatureException;

    public void setSigningKey(PrivateKey signingKey);

    public String getAlgorithmIdentifier();
}
