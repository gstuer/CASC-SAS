package com.gstuer.casc.common.concurrency;

import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.cryptography.Verifier;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;

import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class RequestableVerifier extends RequestableResource<Verifier<?>> {
    private static final long REQUEST_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(250);
    private static final int REQUEST_RETRIES = 3;

    private final String algorithmIdentifier;

    public RequestableVerifier(BlockingQueue<AccessControlMessage<?>> messageEgress, Signer<?> signer,
                               InetAddress keyProvider, String algorithmIdentifier) {
        super(messageEgress, signer, REQUEST_RETRIES, REQUEST_TIMEOUT_NANOS, keyProvider);
        this.algorithmIdentifier = Objects.requireNonNull(algorithmIdentifier);
    }

    @Override
    protected AccessControlMessage<?> constructRequestMessage() {
        try {
            return new KeyExchangeRequestMessage(this.getProvider(), null, this.algorithmIdentifier).sign(this.getSigner());
        } catch (InvalidKeyException | SignatureException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    protected void sendRequestMessage() {
        super.sendRequestMessage();
        System.out.printf("[Request] Key exchange request sent to %s.\n", this.getProvider().getHostAddress());
    }
}
