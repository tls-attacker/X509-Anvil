/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.constants;

public class ExtensionObjectIdentifiers {
    private static final String ID_CE = "2.5.29";
    public static final String AUTHORITY_KEY_IDENTIFIER = ID_CE + ".35";
    public static final String SUBJECT_KEY_IDENTIFIER = ID_CE + ".14";
    public static final String KEY_USAGE = ID_CE + ".15";
    public static final String BASIC_CONSTRAINTS = ID_CE + ".19";
    public static final String UNKNOWN_EXTENSION = "1.2.3.4.5.6.7.8.9";
}
