/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.parameter.*;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.*;
import de.rub.nds.x509anvil.framework.anvil.parameter.name.CNTypeParameter;

public class X509AnvilParameterFactory {

    public static DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        switch ((X509AnvilParameterType) parameterIdentifier.getParameterType()) {
            case CHAIN_LENGTH:
                return new ChainLengthParameter();
            case VERSION:
                return new VersionParameter(parameterIdentifier.getParameterScope());
            case SERIAL_NUMBER:
                return new SerialNumberParameter(parameterIdentifier.getParameterScope());
            case KEY_TYPE:
                return new SignatureHashAndLengthParameter(parameterIdentifier.getParameterScope());
            case NOT_BEFORE:
                return new NotBeforeParameter(parameterIdentifier.getParameterScope());
            case NOT_AFTER:
                return new NotAfterParameter(parameterIdentifier.getParameterScope());
            case CN_TYPE:
                return new CNTypeParameter(parameterIdentifier.getParameterScope());
            case EXTENSIONS_PRESENT:
                return new ExtensionsPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PRESENT:
                return new BasicConstraintsPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_CRITICAL:
                return new BasicConstraintsCriticalParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_CA:
                return new BasicConstraintsCaParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT:
                return new BasicConstraintsPathLenConstraintPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT:
                return new BasicConstraintsPathLenConstraintParameter(parameterIdentifier.getParameterScope());
            default:
                throw new IllegalArgumentException(
                    "Unknown parameter identifier " + parameterIdentifier.getParameterType().toString());
        }
    }

    public ParameterScope resolveParameterScope(String scopeIdentifier) {
        try {
            return X509AnvilParameterScope.fromUniqueIdentifier(scopeIdentifier);
        } catch (NumberFormatException e) {
            return ParameterScope.NO_SCOPE;
        }
    }
}
