/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.value;

public enum NotBeforeValue {
    UTC_TIME,
    UTC_TIME_EARLIEST, // Earliest possible UTCTime data (01.01.1950)
    // removed due to BSI compliance by default
    //GENERALIZED_TIME, // Even though UTC time MUST be used for dates before 2050, the verifier MUST still be able to handle it
    //GENERALIZED_TIME_BEFORE_1950 // RFC is not clear about this case
}
