package com.gstuer.casc.common.cryptography;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public interface Verifier<T extends Key> {
    public boolean verify(byte[] data, DigitalSignature signature) throws InvalidKeyException, SignatureException;

    public T getVerificationKey();

    public void setVerificationKey(T verificationKey);

    public void setVerificationKey(EncodedKey encodedVerificationKey) throws InvalidKeySpecException;

    public String getAlgorithmIdentifier();
}
