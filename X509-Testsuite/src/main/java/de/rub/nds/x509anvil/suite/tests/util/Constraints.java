package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithmLengthPair;

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

    public static boolean allowRsa(SignatureAlgorithmLengthPair value) {
        return value != null && value.getSignatureAlgorithm() == SignatureAlgorithm.RSA_PKCS1;
    }

    public static boolean allowDsa(SignatureAlgorithmLengthPair value) {
        return value != null && value.getSignatureAlgorithm() == SignatureAlgorithm.DSA;
    }


    public static boolean restrictHashForRsa512(HashAlgorithm value) {
        return value != HashAlgorithm.SHA512 && value != HashAlgorithm.SHA384;
    }
}
