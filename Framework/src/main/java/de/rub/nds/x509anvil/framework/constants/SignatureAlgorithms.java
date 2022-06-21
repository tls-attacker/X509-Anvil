/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.constants;

public class SignatureAlgorithms {
    public static final SignatureAlgorithmInfo DSA_WITH_NONE =
        new SignatureAlgorithmInfo.Rsa("2.16.840.1.101.3.4.3.2", "DsaWithNone");
}
