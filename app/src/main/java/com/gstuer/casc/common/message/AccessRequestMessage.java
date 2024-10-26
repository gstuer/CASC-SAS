package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class AccessRequestMessage extends AccessControlMessage<AccessRequestPattern> {
    @Serial
    private static final long serialVersionUID = 5920009290786282627L;

    public AccessRequestMessage(InetAddress source, InetAddress destination, DigitalSignature signature, AccessRequestPattern payload) {
        super(source, destination, signature, payload);
    }

    public AccessRequestMessage(InetAddress destination, DigitalSignature signature, AccessRequestPattern payload) {
        super(destination, signature, payload);
    }

    @Override
    public AccessRequestMessage fromSource(InetAddress source) {
        return new AccessRequestMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public AccessRequestMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new AccessRequestMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public byte[] getSigningData() {
        return this.getPayload().getSigningData();
    }
}
