package de.rub.nds.x509anvil.suite.tests.util;

public class Constraints {

    public static boolean enabled(Boolean value) {
        return value;
    }

    public static boolean disabled(Boolean value) {
        return !value;
    }

    public static boolean allowVersion1(Integer value) {
        return value.equals(0);
    }
}
