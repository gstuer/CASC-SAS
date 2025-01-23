package com.gstuer.casc.common.cryptography;

import java.util.Optional;

public final class AuthenticatorFactory {
    private AuthenticatorFactory() {
    }

    public static Optional<Authenticator<?, ?>> createByIdentifier(String algorithmIdentifier) {
        Authenticator<?, ?> authenticator = null;
        if (algorithmIdentifier.equals(Ed25519Authenticator.ALGORITHM_IDENTIFIER)) {
            authenticator = new Ed25519Authenticator();
        } else if (algorithmIdentifier.endsWith(RsaAuthenticator.ALGORITHM_IDENTIFIER_SUFFIX)) {
            RsaAuthenticator.Algorithm algorithm = RsaAuthenticator.Algorithm.getByAlgorithmIdentifier(algorithmIdentifier);
            authenticator = new RsaAuthenticator(algorithm);
        } else if (algorithmIdentifier.equals(HmacAuthenticator.ALGORITHM_IDENTIFIER)) {
            authenticator = new HmacAuthenticator();
        } else if (algorithmIdentifier.equals(NoOperationAuthenticator.ALGORITHM_IDENTIFIER)) {
            authenticator = new NoOperationAuthenticator();
        }
        return Optional.ofNullable(authenticator);
    }
}
