package com.gstuer.casc.common.concurrency;

import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessRequestMessage;
import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class RequestableAccessDecision extends RequestableResource<AccessDecision> {
    private static final long REQUEST_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(250);
    private static final int REQUEST_RETRIES = 3;

    private final AccessRequestPattern pattern;

    public RequestableAccessDecision(BlockingQueue<AccessControlMessage<?>> messageEgress, Signer<?> signer,
                                     InetAddress decisionProvider, AccessRequestPattern pattern) {
        super(messageEgress, signer, REQUEST_RETRIES, REQUEST_TIMEOUT_NANOS, decisionProvider);
        this.pattern = Objects.requireNonNull(pattern);
    }

    @Override
    protected AccessControlMessage<?> constructRequestMessage() {
        try {
            return new AccessRequestMessage(this.getProvider(), null, this.pattern).sign(this.getSigner());
        } catch (InvalidKeyException | SignatureException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    protected void sendRequestMessage() {
        super.sendRequestMessage();
        System.out.printf("[Request] Access request sent to %s.\n", this.getProvider().getHostAddress());
    }
}
