/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.model;

public enum IssuerType {
    NEXT_IN_CHAIN, // Issuer field is identical to Subject of next cert in chain
    SELF, // Issuer field is identical to the certificate's own Subject field
    OVERRIDE, // Use unrelated issuer
}
