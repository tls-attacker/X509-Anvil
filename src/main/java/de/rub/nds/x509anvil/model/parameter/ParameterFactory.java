package de.rub.nds.x509anvil.model.parameter;

import de.rub.nds.x509anvil.model.ParameterIdentifier;

public class ParameterFactory {
    public static DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        switch(parameterIdentifier.getParameterType()) {
            case CHAIN_LENGTH: return new ChainLengthParameter();
            case VERSION: return new VersionParameter(parameterIdentifier.getParameterScope());
            default: throw new UnsupportedOperationException("Unsupported parameter type: " + parameterIdentifier);
        }
    }
}
