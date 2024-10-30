package com.gstuer.casc.common.cryptography;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a {@link Signer signer} and {@link Verifier verifier} based on the RSA signature scheme using specified
 * digest.
 */
public class RsaAuthenticator extends Authenticator<PrivateKey, PublicKey> {
    public final Algorithm algorithm;

    public RsaAuthenticator(Algorithm algorithm) {
        this.algorithm = Objects.requireNonNull(algorithm);
    }

    @Override
    public DigitalSignature sign(byte[] data) throws InvalidKeyException, SignatureException {
        Signature signer;
        try {
            signer = Signature.getInstance(this.getAlgorithmIdentifier());
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        signer.initSign(this.getSigningKey());
        signer.update(data);
        return new DigitalSignature(signer.sign(), this.getAlgorithmIdentifier());
    }

    @Override
    public boolean verify(byte[] data, DigitalSignature signature) throws InvalidKeyException, SignatureException {
        Signature signer;
        try {
            signer = Signature.getInstance(this.getAlgorithmIdentifier());
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        signer.initVerify(this.getVerificationKey());
        signer.update(data);
        return signer.verify(signature.getData());
    }

    @Override
    public void setVerificationKey(EncodedKey encodedVerificationKey) throws InvalidKeySpecException {
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedVerificationKey.getKey()));
        this.setVerificationKey(publicKey);
    }

    @Override
    public String getAlgorithmIdentifier() {
        return this.algorithm.getAlgorithmIdentifier();
    }

    @Override
    public void initializeKeyPair() {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new IllegalStateException(exception);
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.setSigningKey(keyPair.getPrivate());
        this.setVerificationKey(keyPair.getPublic());
    }

    public enum Algorithm {
        SHA2_256("SHA256withRSA"),
        SHA2_521("SHA512withRSA"),
        SHA3_256("SHA3-256withRSA"),
        SHA3_521("SHA3-512withRSA"),
        MD5("MD5withRSA");

        private final String algorithmIdentifier;

        private Algorithm(String algorithmIdentifier) {
            this.algorithmIdentifier = Objects.requireNonNull(algorithmIdentifier);
        }

        public static Algorithm getByAlgorithmIdentifier(String algorithmIdentifier) {
            return Arrays.stream(Algorithm.values())
                    .filter(entry -> entry.algorithmIdentifier.equals(algorithmIdentifier))
                    .findFirst().orElseThrow();
        }

        public String getAlgorithmIdentifier() {
            return algorithmIdentifier;
        }
    }
}
