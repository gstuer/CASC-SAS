package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.pattern.AccessDecision;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class AccessDecisionMessage extends AccessControlMessage<AccessDecision> {
    @Serial
    private static final long serialVersionUID = 5920009290786282627L;

    public AccessDecisionMessage(InetAddress source, InetAddress destination, DigitalSignature signature, AccessDecision payload) {
        super(source, destination, signature, payload);
    }

    public AccessDecisionMessage(InetAddress destination, DigitalSignature signature, AccessDecision payload) {
        super(destination, signature, payload);
    }

    @Override
    public AccessDecisionMessage fromSource(InetAddress source) {
        return new AccessDecisionMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public AccessDecisionMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new AccessDecisionMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public byte[] getSigningData() {
        return this.getPayload().getSigningData();
    }
}
