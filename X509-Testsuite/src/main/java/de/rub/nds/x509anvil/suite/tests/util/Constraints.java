/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;

public class Constraints {

    public static boolean enabled(Boolean value) {
        if (value == null) return false;
        return value;
    }

    public static boolean disabled(Boolean value) {
        if (value == null) return true;
        return !value;
    }

    public static boolean strictlyDisabled(Boolean value) {
        if (value == null) return false;
        return !value;
    }

    // TODO: enforce version 1?
    public static boolean allowVersion1(Integer value) {
        if (value == null) return false;
        return value.equals(0);
    }

    // TODO: are these still enforced?
    public static boolean allowRsa(SignatureHashAlgorithmKeyLengthPair value) {
        return value != null && value.getSignatureAlgorithm() == SignatureAlgorithm.RSA_PKCS1;
    }

    public static boolean allowDsa(SignatureHashAlgorithmKeyLengthPair value) {
        return value != null && value.getSignatureAlgorithm() == SignatureAlgorithm.DSA;
    }

    public static boolean restrictHashForRsa512(HashAlgorithm value) {
        return value != HashAlgorithm.SHA512 && value != HashAlgorithm.SHA384;
    }
}
