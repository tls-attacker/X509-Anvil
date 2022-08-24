package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.constants.KeyTypeLengthPair;

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

    public static boolean allowVersion1(Integer value) {
        if (value == null) return false;
        return value.equals(0);
    }

    public static boolean allowRsa(KeyTypeLengthPair value) {
        return value != null && value.getKeyType() == KeyType.RSA;
    }
}
