package com.gstuer.casc.common.cryptography;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * Represents an insecure {@link Authenticator authenticator} based on a signature scheme with static signature.
 * This authenticator is intended to be used for performance measurement purposes only.
 * It should never be used in the context of security-critical applications.
 */
public class NoOperationAuthenticator extends Authenticator<Key, Key> {
    public static final String ALGORITHM_IDENTIFIER = "NoOperation";
    public static final byte[] SIGNATURE = new byte[]{0x0, 0x1};

    @Override
    public DigitalSignature sign(byte[] data) throws InvalidKeyException, SignatureException {
        return new DigitalSignature(SIGNATURE, ALGORITHM_IDENTIFIER);
    }

    @Override
    public boolean verify(byte[] data, DigitalSignature signature) {
        return Arrays.equals(SIGNATURE, signature.getData());
    }

    @Override
    public void setVerificationKey(EncodedKey encodedVerificationKey) {
        // Accept every verification key
    }

    @Override
    public String getAlgorithmIdentifier() {
        return ALGORITHM_IDENTIFIER;
    }

    @Override
    public void initializeKeyPair() {
        Key key = new SecretKeySpec(ALGORITHM_IDENTIFIER.getBytes(), ALGORITHM_IDENTIFIER);
        this.setSigningKey(key);
        this.setVerificationKey(key);
    }
}
