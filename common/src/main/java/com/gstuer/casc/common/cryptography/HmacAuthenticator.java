package com.gstuer.casc.common.cryptography;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class HmacAuthenticator extends Authenticator<SecretKey, SecretKey> {
    public static final String ALGORITHM_IDENTIFIER = "HmacSHA512/256";

    @Override
    public void initializeKeyPair() {
        SecureRandom random;
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        byte[] randomBytes = new byte[128];
        random.nextBytes(randomBytes);
        SecretKeySpec keySpec = new SecretKeySpec(randomBytes, this.getAlgorithmIdentifier());
        this.setSigningKey(keySpec);
        this.setVerificationKey(keySpec);
    }

    @Override
    public DigitalSignature sign(byte[] data) throws InvalidKeyException {
        Mac hmac;
        try {
            hmac = Mac.getInstance(this.getAlgorithmIdentifier());
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        hmac.init(this.getSigningKey());
        return new DigitalSignature(hmac.doFinal(data), this.getAlgorithmIdentifier());
    }

    @Override
    public boolean verify(byte[] data, DigitalSignature signature) throws InvalidKeyException {
        Mac hmac;
        try {
            hmac = Mac.getInstance(this.getAlgorithmIdentifier());
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        hmac.init(this.getVerificationKey());
        DigitalSignature verificationSignature = new DigitalSignature(hmac.doFinal(data), this.getAlgorithmIdentifier());
        return verificationSignature.equals(signature);
    }

    @Override
    public void setVerificationKey(EncodedKey encodedVerificationKey) {
        if (!encodedVerificationKey.getAlgorithmIdentifier().equals(this.getAlgorithmIdentifier())) {
            throw new IllegalArgumentException("Incompatible algorithm identifier of encoded key.");
        }
        SecretKeySpec keySpec = new SecretKeySpec(encodedVerificationKey.getKey(), this.getAlgorithmIdentifier());
        this.setVerificationKey(keySpec);
    }

    @Override
    public String getAlgorithmIdentifier() {
        return ALGORITHM_IDENTIFIER;
    }
}
