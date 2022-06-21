/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model.constraint;

import de.rub.nds.x509anvil.framework.model.DerivationScope;
import de.rub.nds.x509anvil.framework.model.ParameterIdentifier;
import de.rwth.swc.coffee4j.model.constraints.Constraint;

import java.util.Set;
import java.util.List;

public class ConditionalConstraint {
    private final Set<ParameterIdentifier> requiredParameters;
    private final Constraint constraint;

    public ConditionalConstraint(Set<ParameterIdentifier> requiredParameters, Constraint constraint) {
        this.requiredParameters = requiredParameters;
        this.constraint = constraint;
    }

    public boolean isApplicableTo(List<ParameterIdentifier> modeledParameters, DerivationScope derivationScope) {
        for (ParameterIdentifier requiredParameter : requiredParameters) {
            if (!modeledParameters
                .contains(requiredParameter) /*
                                              * TODO || !ParameterFactory.getInstance(requiredParameter).canBeModeled(
                                              * TestContext.getInstance(), scope))
                                              */) {
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
