/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;

import java.util.Collections;
import java.util.List;

public class ExtensionsPresentParameter extends BooleanCertificateSpecificParameter {
    // TODO If present, this field is a SEQUENCE of one or more certificate extensions.

    public ExtensionsPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    public ExtensionsPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        // CA certificates must contain BasicConstraints extension
        if (!getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new ExtensionsPresentParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setIncludeExtensions(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);
        // Extensions are only allowed in v3 certificates
        defaultConstraints
            .add(CommonConstraints.valuesOnlyAllowedInV3Certs(derivationScope, this, Collections.singletonList(true)));
        return defaultConstraints;
    }
}
