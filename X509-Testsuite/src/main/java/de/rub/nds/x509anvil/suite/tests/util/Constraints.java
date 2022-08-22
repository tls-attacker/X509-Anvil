package de.rub.nds.x509anvil.suite.tests.util;

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
}
