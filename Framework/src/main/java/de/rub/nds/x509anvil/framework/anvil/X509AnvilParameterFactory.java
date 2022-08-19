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
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.UnknownNonCriticalExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsCaParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPathLenConstraintParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPathLenConstraintPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage.KeyUsageFlagParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.subjectkeyid.SubjectKeyIdentifierPresentParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.extension.KeyUsageExtensionConfig;

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
            case KEY_TYPE:
                return new KeyTypeParameter(parameterIdentifier.getParameterScope());
            case HASH_ALGORITHM:
                return new HashAlgorithmParameter(parameterIdentifier.getParameterScope());
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
            case EXT_UNKNOWN_NONCRITICAL_EXTENSION_PRESENT:
                return new UnknownNonCriticalExtensionPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PRESENT:
                return new BasicConstraintsPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_CRITICAL:
                return new ExtensionCriticalParameter(parameterIdentifier, ExtensionType.BASIC_CONSTRAINTS, X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT);
            case EXT_BASIC_CONSTRAINTS_CA:
                return new BasicConstraintsCaParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT:
                return new BasicConstraintsPathLenConstraintPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT:
                return new BasicConstraintsPathLenConstraintParameter(parameterIdentifier.getParameterScope());
            case EXT_KEY_USAGE_PRESENT:
                return new ExtensionPresentParameter(parameterIdentifier, ExtensionType.KEY_USAGE);
            case EXT_KEY_USAGE_CRITICAL:
                return new ExtensionCriticalParameter(parameterIdentifier, ExtensionType.KEY_USAGE, X509AnvilParameterType.EXT_KEY_USAGE_PRESENT);
            case EXT_KEY_USAGE_DIGITAL_SIGNATURE:
                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.DIGITAL_SIGNATURE);
//            case EXT_KEY_USAGE_NON_REPUDIATION:
//                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.NON_REPUDIATION);
            case EXT_KEY_USAGE_KEY_ENCIPHERMENT:
                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.KEY_ENCIPHERMENT);
            case EXT_KEY_USAGE_DATA_ENCIPHERMENT:
                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.DATA_ENCIPHERMENT);
            case EXT_KEY_USAGE_KEY_AGREEMENT:
                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.KEY_AGREEMENT);
            case EXT_KEY_USAGE_KEY_CERT_SIGN:
                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.KEY_CERT_SIGN);
//            case EXT_KEY_USAGE_CRL_SIGN:
//                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.CRL_SIGN);
//            case EXT_KEY_USAGE_ENCIPHER_ONLY:
//                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.ENCIPHER_ONLY);
//            case EXT_KEY_USAGE_DECIPHER_ONLY:
//                return new KeyUsageFlagParameter(parameterIdentifier, KeyUsageExtensionConfig.DECIPHER_ONLY);
            case EXT_SUBJECT_KEY_IDENTIFIER_PRESENT:
                return new SubjectKeyIdentifierPresentParameter(parameterIdentifier.getParameterScope());
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
