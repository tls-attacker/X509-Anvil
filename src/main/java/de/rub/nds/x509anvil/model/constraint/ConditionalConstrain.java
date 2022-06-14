package de.rub.nds.x509anvil.model.constraint;

import de.rub.nds.x509anvil.model.DerivationScope;
import de.rub.nds.x509anvil.model.ParameterIdentifier;
import de.rub.nds.x509anvil.model.ParameterType;
import de.rwth.swc.coffee4j.model.constraints.Constraint;

import java.util.Set;
import java.util.List;

public class ConditionalConstrain {
    private final Set<ParameterIdentifier> requiredParameters;
    private final Constraint constraint;

    public ConditionalConstrain(Set<ParameterIdentifier> requiredParameters, Constraint constraint) {
        this.requiredParameters = requiredParameters;
        this.constraint = constraint;
    }

    public boolean isApplicableTo(List<ParameterIdentifier> modeledParameters, DerivationScope derivationScope) {
        for (ParameterIdentifier requiredParameter : requiredParameters) {
            if (!modeledParameters.contains(requiredParameter) /* TODO || !ParameterFactory.getInstance(requiredParameter).canBeModeled(TestContext.getInstance(), scope)) */) {
                return false;
            }
        }
        return true;
    }

    public Set<ParameterIdentifier> getRequiredParameters() {
        return requiredParameters;
    }

    public Constraint getConstraint() {
        return constraint;
    }
}
