/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.value;

public enum NotAfterValue {
    UTC_TIME,
    UTC_TIME_LATEST,
    GENERALIZED_TIME_BEFORE_2050,
    GENERALIZED_TIME,
    NO_WELL_DEFINED_EXPIRATION
}
