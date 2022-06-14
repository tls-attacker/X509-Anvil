package de.rub.nds.x509anvil.model;

import de.rub.nds.x509anvil.model.constraint.ValueConstraint;

import java.util.Map;
import java.util.List;

public class DerivationScope {
    private final List<ValueConstraint> valueConstraints;
    private final Map<ParameterIdentifier, String> explicitValues;

    public DerivationScope(List<ValueConstraint> valueConstraints, Map<ParameterIdentifier, String> explicitValues) {
        this.valueConstraints = valueConstraints;
        this.explicitValues = explicitValues;
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
}
