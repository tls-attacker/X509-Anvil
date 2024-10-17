/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.verifier;

public class VerifierResult {
    private final boolean valid;

    public VerifierResult(boolean valid) {
        this.valid = valid;
    }

    public boolean isValid() {
        return valid;
    }
}
