/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import java.util.ArrayList;
import java.util.List;

public abstract class BooleanCertificateSpecificParameter
        extends CertificateSpecificParameter<Boolean> {

    public BooleanCertificateSpecificParameter(ParameterIdentifier parameterIdentifier) {
        super(parameterIdentifier, Boolean.class);
    }

    public BooleanCertificateSpecificParameter(
            Boolean selectedValue, ParameterIdentifier parameterIdentifier) {
        this(parameterIdentifier);
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>> getNonNullParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, Boolean>> parameterValues =
                new ArrayList<>();
        parameterValues.add(generateValue(false));
        parameterValues.add(generateValue(true));
        return parameterValues;
    }
}
