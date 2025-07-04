/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier.adapter;

import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.List;

public class CliVerifierAdapter implements VerifierAdapter {
    private String commandTemplate;

    public CliVerifierAdapter(String commandFormat) {
        this.commandTemplate = commandFormat;
    }

    public String getCommandTemplate() {
        return commandTemplate;
    }

    public void setCommandTemplate(String commandTemplate) {
        this.commandTemplate = commandTemplate;
    }

    @Override
    public VerifierResult invokeVerifier(
            X509CertificateConfig leafCertificateConfig, List<X509Certificate> certificatesChain)
            throws VerifierException {
        return null;
    }
}
