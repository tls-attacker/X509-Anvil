/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.annotation;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Specifies the RFC with section of the test case. Also gives an informative text.
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface Specification {
    @JsonProperty("document")
    String document();

    @JsonProperty("section")
    String section() default "";

    @JsonProperty("text")
    String text() default "";
}