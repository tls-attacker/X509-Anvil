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
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
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
        int minChainLength = AnnotationUtil.resolveMinChainLength(derivationScope.getExtensionContext());
        int maxChainLength = AnnotationUtil.resolveMaxChainLength(derivationScope.getExtensionContext());

        List<DerivationParameter> parameterValues = new ArrayList<>();
        for (int i = minChainLength; i <= maxChainLength; i++) {
            parameterValues.add(this.generateValue(i));
        }
        return parameterValues;
    }

    @Override
    public void preProcessConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {
        // We need to set the chain length before other parameters access the config
        int intermediateCertsModeled = AnnotationUtil.resolveIntermediateCertsModeled(derivationScope.getExtensionContext());
        config.initializeChain(getSelectedValue(), intermediateCertsModeled);
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {}
}
