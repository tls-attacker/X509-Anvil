/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.generator.modifier;

import de.rub.nds.x509attacker.config.X509CertificateConfig;

public interface X509CertificateConfigModifier {
    void apply(X509CertificateConfig config);
}
