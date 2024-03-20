/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VersionParameter extends CertificateSpecificParameter<Integer> {

    public VersionParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.VERSION, parameterScope), Integer.class);
    }

    public VersionParameter(Integer selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    public DerivationParameter<X509CertificateChainConfig, Integer> generateValue(Integer selectedValue) {
        return new VersionParameter(selectedValue, getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Integer>> getNonNullParameterValues(DerivationScope derivationScope) {
        if (!getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(2));
        }
        List<DerivationParameter<X509CertificateChainConfig, Integer>> parameterValues = new ArrayList<>();
        List<Integer> supportedVersions = ContextHelper.getFeatureReport().getSupportedVersions();
        for (Integer version : supportedVersions) {
            parameterValues.add(generateValue(version));
        }

        return parameterValues;
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setVersion(getSelectedValue());
    }
}
