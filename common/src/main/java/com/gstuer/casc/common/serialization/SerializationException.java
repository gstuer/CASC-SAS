package com.gstuer.casc.common.serialization;

import java.io.Serial;

public class SerializationException extends Exception {
    @Serial
    private static final long serialVersionUID = 966868155276175080L;

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SerializationException(Throwable cause) {
        super(cause);
    }
}
