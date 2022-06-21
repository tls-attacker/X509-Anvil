/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model.parameter;

import de.rub.nds.x509anvil.framework.model.DerivationScope;
import de.rub.nds.x509anvil.framework.model.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.model.ParameterScope;
import de.rub.nds.x509anvil.framework.model.ParameterType;
import de.rub.nds.x509anvil.framework.model.constraint.ConditionalConstraint;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;

import java.util.Collections;
import java.util.List;
import java.util.Set;

public abstract class CertificateSpecificParameter<T> extends DerivationParameter<T> {

    public CertificateSpecificParameter(ParameterType parameterType, ParameterScope parameterScope,
        Class<T> valueClass) {
        super(parameterType, parameterScope, valueClass);
    }

    /**
     * Creates a conditional constraint that enforces the parameter value to be null if and only if the certificate that
     * the parameter is associated with is not modelled. For example, if the parameter is associated with an
     * intermediate certificate and the certificate length parameter is 2, we don't need the parameter to be included.
     */
    private ConditionalConstraint createCertificateNotModeledConstraint() {
        Set<ParameterIdentifier> requiredParameters =
            Collections.singleton(new ParameterIdentifier(ParameterScope.GLOBAL, ParameterType.CHAIN_LENGTH));
        Constraint constraint = ConstraintBuilder
            .constrain(getParameterIdentifier().toString(), requiredParameters.stream().findFirst().get().toString())
            .by((ChainLengthParameter chainLengthParam, CertificateSpecificParameter<T> certificateSpecificParam) -> {
                Integer chainLength = chainLengthParam.getSelectedValue();
                T selectedValue = certificateSpecificParam.getSelectedValue();
                return (certificateParameterScopeModeled(getParameterIdentifier().getParameterScope(), chainLength)
                    ^ selectedValue == null);
            });
        return new ConditionalConstraint(requiredParameters, constraint);
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);
        defaultConstraints.add(createCertificateNotModeledConstraint());
        return defaultConstraints;
    }

    private static boolean certificateParameterScopeModeled(ParameterScope parameterScope, int chainLength) {
        switch (parameterScope) {
            case ENTITY_CERT:
                return chainLength >= 1;
            case ROOT_CERT:
                return chainLength >= 2;
            case INTERMEDIATE_CERT:
                return chainLength >= 3;
            default:
                return false; // Not a certificate parameter scope
        }
    }
}
