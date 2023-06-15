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
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.UnknownNonCriticalExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsCaParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPathLenConstraintParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPathLenConstraintPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints.BasicConstraintsPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyidentifier.AuthorityKeyIdentifierPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyidentifier.SubjectKeyIdentifierPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage.KeyUsageFlagParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage.KeyUsagePresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.name.CNTypeParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.name.DomainComponentsPresentParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.name.NameComponentPresentParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
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
            case CN_TYPE:
                return new CNTypeParameter(parameterIdentifier.getParameterScope());
            case NC_COUNTRY_NAME_PRESENT:
                return new NameComponentPresentParameter(parameterIdentifier,
                    AttributeTypeObjectIdentifiers.COUNTRY_NAME, "DE");
            case NC_STATE_PROVINCE_PRESENT:
                return new NameComponentPresentParameter(parameterIdentifier,
                    AttributeTypeObjectIdentifiers.STATE_OR_PROVINCE_NAME, "NRW");
            case NC_LOCALITY_PRESENT:
                return new NameComponentPresentParameter(parameterIdentifier,
                    AttributeTypeObjectIdentifiers.LOCALITY_NAME, "Paderborn");
            case NC_ORGANIZATION_PRESENT:
                return new NameComponentPresentParameter(parameterIdentifier,
                    AttributeTypeObjectIdentifiers.ORGANIZATION_NAME, "UPB");
            case NC_ORGANIZATIONAL_UNIT_PRESENT:
                return new NameComponentPresentParameter(parameterIdentifier,
                    AttributeTypeObjectIdentifiers.ORGANIZATIONAL_UNIT_NAME, "CS");
            case NC_SERIAL_NUMBER_PRESENT:
                return new NameComponentPresentParameter(parameterIdentifier,
                    AttributeTypeObjectIdentifiers.SERIAL_NUMBER, "SERIAL:A3:B4:1337");
            case DOMAIN_COMPONENTS_PRESENT:
                return new DomainComponentsPresentParameter(parameterIdentifier.getParameterScope());
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
                return new ExtensionCriticalParameter(parameterIdentifier, ExtensionType.BASIC_CONSTRAINTS,
                    X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT);
            case EXT_BASIC_CONSTRAINTS_CA:
                return new BasicConstraintsCaParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT:
                return new BasicConstraintsPathLenConstraintPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT:
                return new BasicConstraintsPathLenConstraintParameter(parameterIdentifier.getParameterScope());
            case EXT_KEY_USAGE_PRESENT:
                return new KeyUsagePresentParameter(parameterIdentifier.getParameterScope());
            case EXT_KEY_USAGE_CRITICAL:
                return new ExtensionCriticalParameter(parameterIdentifier, ExtensionType.KEY_USAGE,
                    X509AnvilParameterType.EXT_KEY_USAGE_PRESENT);
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
            case EXT_AUTHORITY_KEY_IDENTIFIER_PRESENT:
                return new AuthorityKeyIdentifierPresentParameter(parameterIdentifier.getParameterScope());
            case EXT_SUBJECT_KEY_IDENTIFIER_PRESENT:
                return new SubjectKeyIdentifierPresentParameter(parameterIdentifier.getParameterScope());
            default:
                throw new IllegalArgumentException(
                    "Unknown parameter identifier " + parameterIdentifier.getParameterType().toString());
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
