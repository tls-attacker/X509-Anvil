/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.value;

public enum NotAfterValue {
    UTC_TIME,
    UTC_TIME_LATEST,
    // GENERALIZED_TIME_BEFORE_2050, not BSI compliant
    GENERALIZED_TIME_AFTER_2050,
}
