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
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.util.ArrayList;
import java.util.List;

public class ChainLengthParameter extends X509AnvilDerivationParameter<Integer> {

    public ChainLengthParameter() {
        super(Integer.class, new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH));
    }

    public ChainLengthParameter(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public DerivationParameter<X509CertificateChainConfig, Integer> generateValue(Integer selectedValue) {
        return new ChainLengthParameter(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> parameterValues = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            parameterValues.add(this.generateValue(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config) {
        config.setChainLength(getSelectedValue());
    }
}
