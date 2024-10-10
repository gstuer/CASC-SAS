package com.gstuer.casc.pep.access.cryptography;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Represents a {@link Signer signer} and {@link Verifier verifier} based on the Ed25519 signature scheme.
 * <p>
 * In order to initialize the object for later verification and signing, use the following approach:
 * <pre>{@code
 * Ed25519 signer = new Ed25519();
 * KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(signer.getAlgorithmIdentifier());
 * KeyPair keyPair = keyPairGenerator.generateKeyPair();
 * signer.setSigningKey(keyPair.getPrivate());
 * signer.setVerificationKey(keyPair.getPublic());
 * }</pre>
 * <p>
 * To sign and verify byte-based data use:
 * <pre>{@code
 * DigitalSignature signature = signer.sign(packet.getRawData());
 * boolean verified = signer.verify(packet.getRawData(), signature);
 * }</pre>
 * <p>
 * To use an externally created public key for verification, encode the key at the signer and decode it at the verifier:
 * <pre>{@code
 * // At the signer
 * byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
 *
 * // At the verifier
 * Ed25519 verifier = new Ed25519();
 * KeyFactory keyFactory = KeyFactory.getInstance(verifier.getAlgorithmIdentifier());
 * PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
 * verifier.setVerificationKey(publicKey);
 * }</pre>
 */
public class Ed25519Authenticator extends Authenticator {
    private static final String ALGORITHM_IDENTIFIER = "Ed25519";

    @Override
    public DigitalSignature sign(byte[] data) throws InvalidKeyException, SignatureException {
        Signature signer;
        try {
            signer = Signature.getInstance(ALGORITHM_IDENTIFIER);
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        signer.initSign(this.getSigningKey());
        signer.update(data);
        return new DigitalSignature(signer.sign(), ALGORITHM_IDENTIFIER);
    }

    @Override
    public boolean verify(byte[] data, DigitalSignature signature) throws InvalidKeyException, SignatureException {
        Signature signer;
        try {
            signer = Signature.getInstance(ALGORITHM_IDENTIFIER);
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        signer.initVerify(this.getVerificationKey());
        signer.update(data);
        return signer.verify(signature.getData());
    }

    @Override
    public String getAlgorithmIdentifier() {
        return ALGORITHM_IDENTIFIER;
    }
}
