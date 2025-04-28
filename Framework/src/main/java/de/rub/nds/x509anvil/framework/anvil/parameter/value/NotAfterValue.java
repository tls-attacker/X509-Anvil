/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.value;

public enum NotAfterValue {
    UTC_TIME,
    UTC_TIME_LATEST,
    GENERALIZED_TIME_BEFORE_2050,
    GENERALIZED_TIME_AFTER_2050,
    // TODO: retain? NO_WELL_DEFINED_EXPIRATION
}
