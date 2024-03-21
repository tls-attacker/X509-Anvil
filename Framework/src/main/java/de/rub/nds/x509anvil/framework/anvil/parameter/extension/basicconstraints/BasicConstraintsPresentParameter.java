/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.util.Collections;
import java.util.List;

public class BasicConstraintsPresentParameter extends ExtensionPresentParameter {
    public BasicConstraintsPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT, parameterScope),
            ExtensionType.BASIC_CONSTRAINTS);
    }

    public BasicConstraintsPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue,
            new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT, parameterScope),
            ExtensionType.BASIC_CONSTRAINTS);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new BasicConstraintsPresentParameter(selectedValue, getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        // BasicConstraints must be present for CA certificates
        if (!getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
