/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

public class NopX509CertificateModifier implements X509CertificateModifier {
    @Override
    public void beforeSigning(X509Certificate certificate, X509CertificateConfig config,
        X509CertificateConfig previousConfig) {
    }
}
