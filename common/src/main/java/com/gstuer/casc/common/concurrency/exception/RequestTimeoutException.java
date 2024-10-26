package com.gstuer.casc.common.concurrency.exception;

import java.io.Serial;

public class RequestTimeoutException extends Exception {
    @Serial
    private static final long serialVersionUID = 7304194719655962418L;

    public RequestTimeoutException(String message) {
        super(message);
    }

    public RequestTimeoutException(Throwable cause) {
        super(cause);
    }

    public RequestTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
