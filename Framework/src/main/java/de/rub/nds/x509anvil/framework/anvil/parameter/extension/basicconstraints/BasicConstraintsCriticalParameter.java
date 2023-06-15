/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionCriticalParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.util.Collections;
import java.util.List;

public class BasicConstraintsCriticalParameter extends ExtensionCriticalParameter {

    public BasicConstraintsCriticalParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_CRITICAL, parameterScope),
            ExtensionType.BASIC_CONSTRAINTS, X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT);
    }

    public BasicConstraintsCriticalParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue,
            new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_CRITICAL, parameterScope),
            ExtensionType.BASIC_CONSTRAINTS, X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new BasicConstraintsCriticalParameter(selectedValue, getParameterScope());
    }

    @Override
    public List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        // BasicConstraints must be critical for CA
        if (!getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }
}
