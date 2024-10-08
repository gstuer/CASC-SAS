package com.gstuer.casc.pep.access.cryptography;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;

public interface Verifier {
    public boolean verify(byte[] data, DigitalSignature signature) throws InvalidKeyException, SignatureException;

    public void setVerificationKey(PublicKey verificationKey);

    public String getAlgorithmIdentifier();
}
