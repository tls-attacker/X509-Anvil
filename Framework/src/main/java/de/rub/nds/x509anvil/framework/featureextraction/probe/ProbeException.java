/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe;

public class ProbeException extends Exception {
    public ProbeException() {
        super();
    }

    public ProbeException(String message) {
        super(message);
    }

    public ProbeException(String message, Throwable cause) {
        super(message, cause);
    }

    public ProbeException(Throwable cause) {
        super(cause);
    }

    protected ProbeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
