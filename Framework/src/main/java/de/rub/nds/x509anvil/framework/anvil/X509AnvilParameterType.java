/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.ParameterType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public enum X509AnvilParameterType implements ParameterType {
    CHAIN_LENGTH,
    VERSION,
    SERIAL_NUMBER,
    NOT_BEFORE,
    NOT_AFTER,
    ISSUER_UNIQUE_ID_PRESENT,
    ISSUER_UNIQUE_ID,
    SUBJECT_UNIQUE_ID_PRESENT,
    SUBJECT_UNIQUE_ID,
    EXTENSIONS_PRESENT,

    // Extensions
    EXT_BASIC_CONSTRAINTS_PRESENT,
    EXT_BASIC_CONSTRAINTS_CRITICAL,
    EXT_BASIC_CONSTRAINTS_CA,
    EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT,
    EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT;

    public static List<X509AnvilParameterType> getCertificateSpecificTypes() {
        List<X509AnvilParameterType> certificateSpecificTypes = new ArrayList<>(Arrays.asList(X509AnvilParameterType.values()));
        certificateSpecificTypes.remove(X509AnvilParameterType.CHAIN_LENGTH);
        return certificateSpecificTypes;
    }
}
