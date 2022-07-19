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
import de.rub.nds.x509anvil.framework.anvil.parameter.*;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionCriticalParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsCaParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPathLenConstraint;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPathLenConstraintPresentParameter;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionType;

public class X509AnvilParameterFactory extends ParameterFactory {
    @Override
    public DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        switch ((X509AnvilParameterType) parameterIdentifier.getParameterType()) {
            case CHAIN_LENGTH:
                return new ChainLengthParameter();
            case VERSION:
                return new VersionParameter(parameterIdentifier.getParameterScope());
            case SERIAL_NUMBER:
                return new SerialNumberParameter(parameterIdentifier.getParameterScope());
            case NOT_BEFORE:
                return new NotBeforeParameter(parameterIdentifier.getParameterScope());
            case NOT_AFTER:
                return new NotAfterParameter(parameterIdentifier.getParameterScope());
            case ISSUER_UNIQUE_ID_PRESENT:
                return new IssuerUniqueIdPresentParameter(parameterIdentifier.getParameterScope());
            case ISSUER_UNIQUE_ID:
                return new IssuerUniqueIdParameter(parameterIdentifier.getParameterScope());
            case SUBJECT_UNIQUE_ID_PRESENT:
                return new SubjectUniqueIdPresentParameter(parameterIdentifier.getParameterScope());
            case SUBJECT_UNIQUE_ID:
                return new SubjectUniqueIdParameter(parameterIdentifier.getParameterScope());
            case EXTENSIONS_PRESENT:
                return new ExtensionsPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PRESENT:
                return new ExtensionPresentParameter(parameterIdentifier, ExtensionType.BASIC_CONSTRAINTS);
            case EXT_BASIC_CONSTRAINTS_CRITICAL:
                return new ExtensionCriticalParameter(parameterIdentifier, ExtensionType.BASIC_CONSTRAINTS, X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT);
            case EXT_BASIC_CONSTRAINTS_CA:
                return new BasicConstraintsCaParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT:
                return new BasicConstraintsPathLenConstraintPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT:
                return new BasicConstraintsPathLenConstraint(parameterIdentifier.getParameterScope());
            default:
                throw new IllegalArgumentException("Unknown parameter identifier " + parameterIdentifier.getParameterType().toString());
        }
    }

    @Override
    public ParameterScope resolveParameterScope(String scopeIdentifier) {
        try {
            return X509AnvilParameterScope.fromUniqueIdentifier(scopeIdentifier);
        } catch (NumberFormatException e) {
            return ParameterScope.NO_SCOPE;
        }
    }
}
