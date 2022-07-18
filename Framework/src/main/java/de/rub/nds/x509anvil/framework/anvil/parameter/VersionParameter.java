/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class VersionParameter extends CertificateSpecificParameter<BigInteger> {

    public VersionParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.VERSION, parameterScope), BigInteger.class);
    }

    public VersionParameter(BigInteger selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    public DerivationParameter<X509CertificateChainConfig, BigInteger> generateValue(BigInteger selectedValue) {
        return new VersionParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter> getParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> parameterValues = new ArrayList<>();
        parameterValues.add(generateValue(null)); // If we don't want this parameter to be modelled (i.e. ParameterScope is not in use)
        parameterValues.add(generateValue(BigInteger.valueOf(0))); // Version 1
        parameterValues.add(generateValue(BigInteger.valueOf(1))); // Version 2
        parameterValues.add(generateValue(BigInteger.valueOf(2))); // Version 3

        return parameterValues;
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {
        if (getSelectedValue() != null) {
            getCertificateConfigByScope(config).setVersion(getSelectedValue());
        }
    }
}
