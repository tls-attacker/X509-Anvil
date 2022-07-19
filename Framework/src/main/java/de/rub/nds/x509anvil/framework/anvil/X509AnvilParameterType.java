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

public enum X509AnvilParameterType implements ParameterType {
    CHAIN_LENGTH,
    VERSION,
    SERIAL_NUMBER,
    NOT_BEFORE,
    NOT_AFTER,
    ISSUER_UNIQUE_ID_PRESENT,
    ISSUER_UNIQUE_ID
}
