package com.gstuer.casc.common.cryptography;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public interface Verifier {
    public boolean verify(byte[] data, DigitalSignature signature) throws InvalidKeyException, SignatureException;

    public PublicKey getVerificationKey();

    public void setVerificationKey(PublicKey verificationKey);

    public void setVerificationKey(EncodedKey encodedVerificationKey) throws InvalidKeySpecException;

    public String getAlgorithmIdentifier();
}
