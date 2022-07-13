/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.coffee4j.model;

import de.rub.nds.x509anvil.framework.junit.context.TestContext;
import de.rub.nds.x509anvil.framework.model.ParameterModelFactory;
import de.rwth.swc.coffee4j.junit.provider.model.ModelProvider;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumer;

public class ScopedModelProvider implements ModelProvider, AnnotationConsumer<TestModel> {
    private TestModel model;

    @Override
    public void accept(TestModel model) {
        this.model = model;
    }

    @Override
    public InputParameterModel provide(ExtensionContext extensionContext) {
        DerivationScope derivationScope = new DerivationScope(extensionContext, model);
        return ParameterModelFactory.generateModel(derivationScope, TestContext.getInstance());
    }
}
