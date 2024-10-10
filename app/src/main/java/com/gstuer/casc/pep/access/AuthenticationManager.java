package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.Authenticator;
import com.gstuer.casc.pep.access.cryptography.Ed25519Authenticator;
import com.gstuer.casc.pep.access.cryptography.Signer;
import com.gstuer.casc.pep.access.cryptography.Verifier;
import com.gstuer.casc.pep.access.exception.RequestTimeoutException;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class AuthenticationManager {
    private final Authenticator authenticator;
    private final ConcurrentMap<InetAddress, ConcurrentMap<String, VerifierRequest>> verifiers;
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
        Map<String, VerifierRequest> hostVerifiers = this.verifiers.computeIfAbsent(externalHost, key -> new ConcurrentHashMap<>());
        VerifierRequest verifier = hostVerifiers.computeIfAbsent(algorithmIdentifier, key -> new VerifierRequest());
        return verifier.get(algorithmIdentifier, externalHost);
    }

    private final class VerifierRequest {
        private static final long REQUEST_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(25);
        private static final long REQUEST_RETRIES = 4;

        private final ReadWriteLock lock = new ReentrantReadWriteLock();
        private final Condition empty = this.lock.writeLock().newCondition();
        private volatile Verifier verifier;
        private volatile LocalDateTime requestTime;

        public Verifier get(String algorithmIdentifier, InetAddress externalHost) throws RequestTimeoutException {
            Lock readLock = this.lock.readLock();
            Lock writeLock = this.lock.writeLock();
            readLock.lock();
            try {
                if (verifier == null) {
                    readLock.unlock();
                    writeLock.lock();
                    try {
                        int count = 0;
                        while (verifier == null) {
                            try {
                                if (count > REQUEST_RETRIES) {
                                    break;
                                }
                                if (isUnavailable() && !isRequestPending()) {
                                    // TODO Add optional signature to request message
                                    KeyExchangeRequestMessage message = new KeyExchangeRequestMessage(externalHost, null, algorithmIdentifier);
                                    AuthenticationManager.this.messageEgress.offer(message);
                                    this.requestTime = LocalDateTime.now();
                                    System.out.printf("[AM] Key exchange request sent to %s.\n", externalHost.getHostAddress());
                                }
                                empty.awaitNanos(REQUEST_TIMEOUT_NANOS);
                                count++;
                            } catch (InterruptedException exception) {
                                continue;
                            }
                        }
                        readLock.lock();
                    } finally {
                        this.empty.signalAll();
                        writeLock.unlock();
                    }
                }
                if (verifier == null) {
                    throw new RequestTimeoutException("Unsatisfied request reached maximum number of retries.");
                }
                return verifier;
            } finally {
                readLock.unlock();
            }
        }

        public void set(Verifier verifier) {
            Lock writeLock = this.lock.writeLock();
            writeLock.lock();
            this.verifier = verifier;
            this.empty.signalAll();
            writeLock.unlock();
        }

        public boolean isUnavailable() {
            Lock readLock = this.lock.readLock();
            readLock.lock();
            try {
                return verifier == null;
            } finally {
                readLock.unlock();
            }
        }

        public boolean isRequestPending() {
            Lock readLock = this.lock.readLock();
            readLock.lock();
            try {
                return requestTime != null && LocalDateTime.now().isBefore(requestTime.plusNanos(REQUEST_TIMEOUT_NANOS));
            } finally {
                readLock.unlock();
            }
        }
    }
}
