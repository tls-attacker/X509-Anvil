/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model.parameter;

public class ParameterFactory {
    public static DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        switch (parameterIdentifier.getParameterType()) {
            case CHAIN_LENGTH:
                return new ChainLengthParameter();
            case VERSION:
                return new VersionParameter(parameterIdentifier.getParameterScope());
            default:
                throw new UnsupportedOperationException("Unsupported parameter type: " + parameterIdentifier);
        }
    }
}
