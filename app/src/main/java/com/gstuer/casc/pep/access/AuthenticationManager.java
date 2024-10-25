package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.concurrency.RequestableVerifier;
import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.cryptography.Ed25519Authenticator;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.cryptography.Verifier;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.pep.access.exception.RequestTimeoutException;

import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class AuthenticationManager {
    private final Authenticator authenticator;
    private final ConcurrentMap<InetAddress, ConcurrentMap<String, RequestableVerifier>> verifiers;
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;

    public AuthenticationManager(BlockingQueue<AccessControlMessage<?>> messageEgress) {
        this.messageEgress = Objects.requireNonNull(messageEgress);
        // Initialize the default signer for this manager
        this.authenticator = new Ed25519Authenticator();
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(this.authenticator.getAlgorithmIdentifier());
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new IllegalStateException(exception);
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.authenticator.setSigningKey(keyPair.getPrivate());
        this.authenticator.setVerificationKey(keyPair.getPublic());

        // Initialize verifier map for external hosts
        this.verifiers = new ConcurrentHashMap<>();
    }

    public Signer getSigner() {
        return this.authenticator;
    }

    public Verifier getVerifier(String algorithmIdentifier, InetAddress externalHost) throws RequestTimeoutException {
        Map<String, RequestableVerifier> hostVerifiers = this.verifiers.computeIfAbsent(externalHost,
                key -> new ConcurrentHashMap<>());
        RequestableVerifier verifier = hostVerifiers.computeIfAbsent(algorithmIdentifier,
                key -> new RequestableVerifier(this.messageEgress, this.getSigner(), externalHost, algorithmIdentifier));
        return verifier.get();
    }

    public void processMessage(KeyExchangeRequestMessage message) {
        // Ignore message if requested type of authenticator not in use
        if (!message.getPayload().equals(this.authenticator.getAlgorithmIdentifier())) {
            System.err.println("[AM] Key request rejected: Illegal algorithm.");
            return;
        }

        // Encode public key of authenticator in use
        EncodedKey encodedKey = new EncodedKey(this.authenticator.getAlgorithmIdentifier(),
                this.authenticator.getVerificationKey().getEncoded());
        KeyExchangeMessage response = new KeyExchangeMessage(message.getSource(), null, encodedKey);
        this.signMessage(response).ifPresent(this.messageEgress::offer);
    }

    public void processMessage(KeyExchangeMessage message) {
        // Fetch relevant information from received message
        InetAddress externalHost = message.getSource();
        EncodedKey encodedKey = message.getPayload();
        String algorithmIdentifier = encodedKey.getAlgorithmIdentifier();

        // Get or create corresponding verifier entry in verifiers map
        Map<String, RequestableVerifier> hostVerifiers = this.verifiers.computeIfAbsent(externalHost,
                key -> new ConcurrentHashMap<>());
        RequestableVerifier verifierRequest = hostVerifiers.computeIfAbsent(algorithmIdentifier,
                key -> new RequestableVerifier(this.messageEgress, this.getSigner(), externalHost, algorithmIdentifier));

        // TODO Replace with some kind of polymorphic verifier solution
        // Initialize public key & verifier based on encoded key material
        Verifier verifier;
        try {
            switch (algorithmIdentifier) {
                case Ed25519Authenticator.ALGORITHM_IDENTIFIER:
                    verifier = new Ed25519Authenticator();
                    verifier.setVerificationKey(encodedKey);
                    break;
                default:
                    System.err.println("[AM] Key exchange failed: Unknown algorithm.");
                    return;
            }
        } catch (InvalidKeySpecException exception) {
            System.err.println("[AM] Key exchange failed: " + exception.getMessage());
            return;
        }

        // Verify received message with initialized verifier
        if (message.hasSignature()) {
            try {
                if (message.verify(verifier)) {
                    // TODO Add handling for already existing key -> Spoofing risk?
                    verifierRequest.set(verifier);
                }
            } catch (SignatureException | InvalidKeyException exception) {
                System.out.println("[AM] Verification failed: " + exception.getMessage());
                return;
            }
        }
    }

    public boolean verifyMessage(AccessControlMessage<?> message) {
        InetAddress source = message.getSource();
        // Check if the message has a signature
        if (!message.hasSignature()) {
            System.out.printf("[AM] %s without signature from %s.\n", message.getClass().getSimpleName(), source.getHostAddress());
            return false;
        }

        // Get the appropriate verifier and verify the appended signature
        try {
            Verifier verifier = this.getVerifier(message.getSignature().getAlgorithmIdentifier(), source);
            return message.verify(verifier);
        } catch (SignatureException | InvalidKeyException | RequestTimeoutException exception) {
            System.out.println("[AM] Verification failed: " + exception.getMessage());
            return false;
        }
    }

    public Optional<AccessControlMessage<?>> signMessage(AccessControlMessage<?> message) {
        try {
            return Optional.of(message.sign(this.authenticator));
        } catch (SignatureException | InvalidKeyException exception) {
            System.out.println("[AM] Signing failed: " + exception.getMessage());
            return Optional.empty();
        }
    }
}
