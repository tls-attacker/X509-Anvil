/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.annotation;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** Specifies the RFC with section of the test case. Also gives an informative text. */
@Retention(RetentionPolicy.RUNTIME)
public @interface Specification {
    @JsonProperty("document")
    String document();

    @JsonProperty("section")
    String section() default "";

    @JsonProperty("text")
    String text() default "";
}
