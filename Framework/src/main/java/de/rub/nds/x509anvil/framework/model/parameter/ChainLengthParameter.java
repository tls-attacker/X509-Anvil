/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model.parameter;

import de.rub.nds.x509anvil.framework.TestContext;
import de.rub.nds.x509anvil.framework.model.DerivationScope;
import de.rub.nds.x509anvil.framework.model.ParameterScope;
import de.rub.nds.x509anvil.framework.model.ParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.util.ArrayList;
import java.util.List;

public class ChainLengthParameter extends DerivationParameter<Integer> {

    public ChainLengthParameter() {
        super(ParameterType.CHAIN_LENGTH, ParameterScope.GLOBAL, Integer.class);
    }

    public ChainLengthParameter(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public DerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new ChainLengthParameter(selectedValue);
    }

    @Override
    public List<DerivationParameter<Integer>> getParameterValues(TestContext testContext,
        DerivationScope derivationScope) {
        List<DerivationParameter<Integer>> parameterValues = new ArrayList<>();
        for (int i = 0; i <= 3; i++) {
            parameterValues.add(this.generateValue(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, TestContext testContext) {
        // TODO
    }
}
