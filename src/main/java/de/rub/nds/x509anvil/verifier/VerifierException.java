package de.rub.nds.x509anvil.verifier;

public class VerifierException extends Exception {
    public VerifierException() {
        super();
    }

    public VerifierException(String message) {
        super(message);
    }

    public VerifierException(String message, Throwable cause) {
        super(message, cause);
    }

    public VerifierException(Throwable cause) {
        super(cause);
    }

    protected VerifierException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
