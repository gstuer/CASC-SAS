package com.gstuer.casc.common.cryptography;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;

public interface Signer<T extends Key> {
    public DigitalSignature sign(byte[] data) throws InvalidKeyException, SignatureException;

    public default DigitalSignature sign(Signable data) throws InvalidKeyException, SignatureException {
        return sign(data.getSigningData());
    }

    public void setSigningKey(T signingKey);

    public String getAlgorithmIdentifier();
}
