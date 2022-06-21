/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.model;

public enum Signer {
    NEXT_IN_CHAIN, // Use private key of next ca certificate in chain
    SELF, // Use own private key
    OVERRIDE // Use unrelated private key supplied via config
}
