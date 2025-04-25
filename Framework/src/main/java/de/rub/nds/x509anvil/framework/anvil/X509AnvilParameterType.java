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
import de.rub.nds.anvilcore.model.parameter.ParameterType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public enum X509AnvilParameterType implements ParameterType {
    CHAIN_LENGTH,
    VERSION,
    SERIAL_NUMBER,
    KEY_TYPE,
    NOT_BEFORE,
    NOT_AFTER,
    CN_TYPE,
    NC_COUNTRY_NAME_PRESENT,
    NC_STATE_PROVINCE_PRESENT,
    NC_LOCALITY_PRESENT,
    NC_ORGANIZATION_PRESENT,
    NC_ORGANIZATIONAL_UNIT_PRESENT,
    NC_SERIAL_NUMBER_PRESENT,
    DOMAIN_COMPONENTS_PRESENT,
    ISSUER_UNIQUE_ID_PRESENT,
    ISSUER_UNIQUE_ID,
    SUBJECT_UNIQUE_ID_PRESENT,
    SUBJECT_UNIQUE_ID,
    EXTENSIONS_PRESENT,

    // Unknown non-critical extension
    EXT_UNKNOWN_NONCRITICAL_EXTENSION_PRESENT,

    // SubjectKeyIdentifier extension
    EXT_AUTHORITY_KEY_IDENTIFIER_PRESENT,
    EXT_SUBJECT_KEY_IDENTIFIER_PRESENT,

    // BasicConstraints extension
    EXT_BASIC_CONSTRAINTS_PRESENT,
    EXT_BASIC_CONSTRAINTS_CRITICAL,
    EXT_BASIC_CONSTRAINTS_CA,
    EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT,
    EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT,

    // KeyUsage extension
    EXT_KEY_USAGE_PRESENT,
    EXT_KEY_USAGE_CRITICAL,
    EXT_KEY_USAGE_DIGITAL_SIGNATURE,
    // EXT_KEY_USAGE_NON_REPUDIATION,
    EXT_KEY_USAGE_KEY_ENCIPHERMENT,
    EXT_KEY_USAGE_DATA_ENCIPHERMENT,
    EXT_KEY_USAGE_KEY_AGREEMENT,
    EXT_KEY_USAGE_KEY_CERT_SIGN,
    // EXT_KEY_USAGE_CRL_SIGN,
    // EXT_KEY_USAGE_ENCIPHER_ONLY,
    // EXT_KEY_USAGE_DECIPHER_ONLY
    ;

    // TODO: probably delete?
    public static List<X509AnvilParameterType> getCertificateSpecificTypes() {
        List<X509AnvilParameterType> certificateSpecificTypes =
            new ArrayList<>(Arrays.asList(X509AnvilParameterType.values()));
        certificateSpecificTypes.remove(X509AnvilParameterType.CHAIN_LENGTH);
        return certificateSpecificTypes;
    }

    @Override
    public DerivationParameter getInstance(ParameterScope scope) {
        return X509AnvilParameterFactory.getInstance(new ParameterIdentifier(this, scope));
    }

    @Override
    public String toString() {
        return this.name().toLowerCase();
    }
}
