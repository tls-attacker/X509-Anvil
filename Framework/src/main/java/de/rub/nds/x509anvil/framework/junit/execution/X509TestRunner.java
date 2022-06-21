/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.junit.execution;

import de.rub.nds.x509anvil.framework.model.ParameterCombination;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import org.junit.jupiter.api.extension.ExtensionContext;

public class X509TestRunner {
    private X509CertificateChainConfig preparedConfig;
    private ParameterCombination parameterCombination;

    public X509TestRunner(ExtensionContext extensionContext) {
    }

    public X509CertificateChainConfig getPreparedConfig() {
        return preparedConfig;
    }

    public void setPreparedConfig(X509CertificateChainConfig preparedConfig) {
        this.preparedConfig = preparedConfig;
    }

    public ParameterCombination getParameterCombination() {
        return parameterCombination;
    }

    public void setParameterCombination(ParameterCombination parameterCombination) {
        this.parameterCombination = parameterCombination;
    }
}
