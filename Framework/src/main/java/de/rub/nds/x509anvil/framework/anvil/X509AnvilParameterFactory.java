/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterFactory;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.parameter.ChainLengthParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.VersionParameter;

public class X509AnvilParameterFactory extends ParameterFactory {
    @Override
    public DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        switch ((X509AnvilParameterType) parameterIdentifier.getParameterType()) {
            case CHAIN_LENGTH:
                return new ChainLengthParameter();
            case VERSION:
                return new VersionParameter(parameterIdentifier.getParameterScope());
            default:
                throw new IllegalArgumentException("Unknown parameter identifier " + parameterIdentifier.getParameterType().toString());
        }
    }

    @Override
    public ParameterScope resolveParameterScope(String scopeIdentifier) {
        try {
            ParameterScopeEnum parameterScopeValue = ParameterScopeEnum.valueOf(scopeIdentifier);
            return new X509AnvilParameterScope(parameterScopeValue);
        } catch (IllegalArgumentException e) {
            return ParameterScope.NO_SCOPE;
        }
    }
}
