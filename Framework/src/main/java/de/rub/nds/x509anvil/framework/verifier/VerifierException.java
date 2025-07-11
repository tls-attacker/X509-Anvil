/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier;

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

    protected VerifierException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
