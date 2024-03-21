/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import java.util.List;

public interface VerifierAdapter {
    VerifierResult invokeVerifier(List<X509Certificate> certificatesChain, X509CertificateChainConfig chainConfig)
        throws VerifierException;
}
