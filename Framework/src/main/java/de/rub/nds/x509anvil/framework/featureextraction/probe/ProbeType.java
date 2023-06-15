/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

public enum ProbeType {
    VERSION,
    SIGNATURE_ALGORITHM,
    KEY_LENGTH,
    EXTENSION,
    DIGITAL_SIGNATURE_KEY_USAGE_REQUIRED
}
