package com.gstuer.casc.common.cryptography;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SignatureException;

public interface Signer {
    public DigitalSignature sign(byte[] data) throws InvalidKeyException, SignatureException;

    public default DigitalSignature sign(Signable data) throws InvalidKeyException, SignatureException {
        return sign(data.getSigningData());
    }

    public void setSigningKey(PrivateKey signingKey);

    public String getAlgorithmIdentifier();
}
