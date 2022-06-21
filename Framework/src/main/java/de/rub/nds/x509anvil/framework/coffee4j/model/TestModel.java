/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.coffee4j.model;

import de.rub.nds.x509anvil.framework.model.TestModelType;
import de.rub.nds.x509anvil.framework.model.TestModelType;
import de.rwth.swc.coffee4j.junit.provider.model.ModelSource;

import java.lang.annotation.*;

@Inherited
@Target({ ElementType.METHOD, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@ModelSource(ScopedModelProvider.class)
public @interface TestModel {
    String name() default "X509-Verifier Test";

    TestModelType model() default TestModelType.DEFAULT;
}
