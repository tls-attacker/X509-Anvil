/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

abstract class X509AnvilDerivationParameter<T>
        extends DerivationParameter<X509CertificateChainConfig, T> {
    public X509AnvilDerivationParameter(
            Class<T> valueClass, ParameterIdentifier parameterIdentifier) {
        super(valueClass, X509CertificateChainConfig.class, parameterIdentifier);
    }
}
