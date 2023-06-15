/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.value;

public enum NotBeforeValue {
    UTC_TIME,
    UTC_TIME_EARLIEST, // Earliest possible UTCTime data (01.01.1950)
    GENERALIZED_TIME, // Even though UTC time MUST be used for dates before 2050, the verifier MUST still be able to
                      // handle it
    GENERALIZED_TIME_BEFORE_1950 // RFC is not clear about this case
}
