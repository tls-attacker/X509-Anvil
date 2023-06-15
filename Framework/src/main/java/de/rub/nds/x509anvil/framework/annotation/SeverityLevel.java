/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.annotation;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.x509anvil.framework.constants.Severity;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Specifies the {@link Severity} level of the test should it fail.
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface SeverityLevel {
    @JsonProperty("severity")
    Severity value();
}
