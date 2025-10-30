/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.parameter.*;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.*;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage.KeyUsageAdditionalUsagesParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.subjectalternativename.SubjectAlternativeNamePresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.subjectalternativename.SubjectAlternativeNameValuesParameter;

public class X509AnvilParameterFactory {

    public static DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        return switch ((X509AnvilParameterType) parameterIdentifier.getParameterType()) {
            case CHAIN_LENGTH -> new ChainLengthParameter();
            case VERSION -> new VersionParameter(parameterIdentifier.getParameterScope());
            case SERIAL_NUMBER -> new SerialNumberParameter(parameterIdentifier.getParameterScope());
            case KEY_TYPE -> new SignatureHashAndLengthParameter(parameterIdentifier.getParameterScope());
            case NOT_BEFORE -> new NotBeforeParameter(parameterIdentifier.getParameterScope());
            case NOT_AFTER -> new NotAfterParameter(parameterIdentifier.getParameterScope());
            case EXTENSIONS_PRESENT -> new ExtensionsPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PRESENT -> new BasicConstraintsPresentParameter(
                    parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_CRITICAL -> new BasicConstraintsCriticalParameter(
                    parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT ->
                    new BasicConstraintsPathLenConstraintPresentParameter(
                            parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT -> new BasicConstraintsPathLenConstraintParameter(
                    parameterIdentifier.getParameterScope());
            case EXT_SUBJECT_ALT_NAME_PRESENT ->
                    new SubjectAlternativeNamePresentParameter(parameterIdentifier.getParameterScope());
            case EXT_SUBJECT_ALT_NAME_VALUES ->  new SubjectAlternativeNameValuesParameter(parameterIdentifier.getParameterScope());
            case EXT_KEY_USAGE_ADDITIONAL -> new KeyUsageAdditionalUsagesParameter(parameterIdentifier.getParameterScope());
        };
    }
}
