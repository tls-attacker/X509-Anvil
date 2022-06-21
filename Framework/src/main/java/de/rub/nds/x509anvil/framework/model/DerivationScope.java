/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model;

import de.rub.nds.x509anvil.framework.coffee4j.model.TestModel;
import de.rub.nds.x509anvil.framework.model.constraint.ValueConstraint;
import de.rub.nds.x509anvil.framework.coffee4j.model.TestModel;
import de.rub.nds.x509anvil.framework.model.constraint.ValueConstraint;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

public class DerivationScope {
    private final int testStrength;
    private final List<ValueConstraint> valueConstraints;
    private final Map<ParameterIdentifier, String> explicitValues;
    private final TestModelType testModel;

    public DerivationScope(ExtensionContext extensionContext, TestModel testModel) {
        // TODO: Set attributes from extensionContext
        this.testStrength = 2;
        this.valueConstraints = new ArrayList<>();
        this.explicitValues = new HashMap<>();
        this.testModel = testModel.model();
    }

    public DerivationScope(ExtensionContext extensionContext) {
        // TODO: Set attributes from extensionContext
        this.testStrength = 2;
        this.valueConstraints = new ArrayList<>();
        this.explicitValues = new HashMap<>();
        this.testModel = TestModelType.DEFAULT;
    }

    public int getTestStrength() {
        return testStrength;
    }

    public boolean hasExplicitValues(ParameterIdentifier parameterIdentifier) {
        return explicitValues.containsKey(parameterIdentifier);
    }

    public Map<ParameterIdentifier, String> getExplicitValues() {
        return explicitValues;
    }

    public List<ValueConstraint> getValueConstraints() {
        return valueConstraints;
    }

    public TestModelType getTestModel() {
        return testModel;
    }
}
