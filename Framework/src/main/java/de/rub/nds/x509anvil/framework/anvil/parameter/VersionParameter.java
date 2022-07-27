/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.ArrayList;
import java.util.Arrays;
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
        return new VersionParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter> getParameterValues(DerivationScope derivationScope) {
        // V1, V2 are not supported for CA certificates
        if (!getParameterScope().isEntity()) {
            return Arrays.asList(generateValue(null), generateValue(2));
        }
        return super.getParameterValues(derivationScope);
    }

    @Override
    public List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> parameterValues = new ArrayList<>();

        List<Integer> supportedVersions = ((X509AnvilContextDelegate) AnvilContext.getInstance()
                .getApplicationSpecificContextDelegate()).getFeatureReport().getSupportedVersions();
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
