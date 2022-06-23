/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model.parameter;

import de.rub.nds.x509anvil.framework.junit.context.TestContext;
import de.rub.nds.x509anvil.framework.model.ParameterScope;
import de.rub.nds.x509anvil.framework.model.DerivationScope;
import de.rub.nds.x509anvil.framework.model.ParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class VersionParameter extends CertificateSpecificParameter<BigInteger> {

    public VersionParameter(ParameterScope parameterScope) {
        super(ParameterType.VERSION, parameterScope, BigInteger.class);
    }

    public VersionParameter(BigInteger selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    public DerivationParameter<BigInteger> generateValue(BigInteger selectedValue) {
        return new VersionParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter<BigInteger>> getParameterValues(TestContext testContext,
        DerivationScope derivationScope) {
        List<DerivationParameter<BigInteger>> parameterValues = new ArrayList<>();
        parameterValues.add(generateValue(null)); // If we don't want this parameter to be modelled (i.e. ParameterScope
                                                  // is not in use)
        parameterValues.add(generateValue(BigInteger.valueOf(-1))); // Represents invalid negative values
        parameterValues.add(generateValue(BigInteger.valueOf(0))); // Version 1
        parameterValues.add(generateValue(BigInteger.valueOf(1))); // Version 2
        parameterValues.add(generateValue(BigInteger.valueOf(2))); // Version 3
        parameterValues.add(generateValue(BigInteger.valueOf(3))); // Represents invalid positive values
        parameterValues.add(generateValue(new BigInteger("FFEEDDCCBBAA9988776655443322110011223344", 16))); // Represents
                                                                                                            // really
                                                                                                            // big
                                                                                                            // integers
        return parameterValues;
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, TestContext testContext) {
        if (getSelectedValue() != null) {
            getCertificateConfigByScope(config).setVersion(getSelectedValue());
        }
    }
}
