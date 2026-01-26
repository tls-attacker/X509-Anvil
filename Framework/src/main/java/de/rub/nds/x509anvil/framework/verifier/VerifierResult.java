/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier;

import de.rub.nds.x509attacker.x509.model.X509Certificate;

import java.util.List;

public class VerifierResult {
    private final boolean valid;
    private final List<X509Certificate> certificatesChain;

    public VerifierResult(boolean valid, List<X509Certificate> certificatesChain) {
        this.valid = valid;
        this.certificatesChain = certificatesChain;
    }

    public boolean isValid() {
        return valid;
    }

    public List<X509Certificate> getCertificatesChain() {
        return certificatesChain;
    }
}
