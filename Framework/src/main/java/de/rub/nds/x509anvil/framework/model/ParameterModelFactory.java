/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model;

import de.rub.nds.x509anvil.framework.TestContext;
import de.rub.nds.x509anvil.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.x509anvil.framework.model.parameter.DerivationParameter;
import de.rub.nds.x509anvil.framework.model.parameter.ParameterFactory;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class ParameterModelFactory {
    private static final Logger LOGGER = LogManager.getLogger();

    public static InputParameterModel generateModel(DerivationScope derivationScope, TestContext testContext) {
        List<ParameterIdentifier> parameterIdentifiers = getParameterIdentifiersForScope(derivationScope);
        Parameter.Builder[] parameterBuilders =
            getParameterBuilders(parameterIdentifiers, derivationScope, testContext);
        Constraint[] constraints = getConstraints(parameterIdentifiers, derivationScope, testContext);

        return InputParameterModel.inputParameterModel("dynamic-model").strength(derivationScope.getTestStrength())
            .parameters(parameterBuilders).exclusionConstraints(constraints).build();
    }

    public static boolean mustUseSimpleModel(TestContext testContext, DerivationScope scope) {
        List<ParameterIdentifier> parameterIdentifiers = getParameterIdentifiersForScope(scope);
        Parameter.Builder[] builders = getParameterBuilders(parameterIdentifiers, scope, testContext);
        return builders.length == 1;
    }

    private static Parameter.Builder[] getParameterBuilders(List<ParameterIdentifier> parameterIdentifiers,
        DerivationScope derivationScope, TestContext testContext) {
        List<Parameter.Builder> parameterBuilders = new ArrayList<>();
        for (ParameterIdentifier parameterIdentifier : parameterIdentifiers) {
            DerivationParameter parameter = ParameterFactory.getInstance(parameterIdentifier);
            if (parameter.canBeModeled(testContext, derivationScope)) {
                parameterBuilders.add(parameter.getParameterBuilder(testContext, derivationScope));
            }
        }
        return parameterBuilders.toArray(new Parameter.Builder[0]);
    }

    private static List<ParameterIdentifier> getParameterIdentifiersForScope(DerivationScope derivationScope) {
        // TODO Implement out-of-scope exclusion with feature extraction
        return getParameterIdentifiersOfModel(derivationScope);
    }

    private static List<ParameterIdentifier> getParameterIdentifiersOfModel(DerivationScope derivationScope) {
        // Here we can add specific test models to exclude certain parameters
        return getDefaultModelParameterIdentifiers(derivationScope);
    }

    private static List<ParameterIdentifier> getDefaultModelParameterIdentifiers(DerivationScope derivationScope) {
        List<ParameterIdentifier> parameterIdentifiers = new ArrayList<>();

        // Add global parameters
        parameterIdentifiers.add(new ParameterIdentifier(ParameterScope.GLOBAL, ParameterType.CHAIN_LENGTH));

        // Add certificate-specific parameters
        for (ParameterScope certParameterScope : ParameterScope.getCertificateScopes()) {
            parameterIdentifiers.add(new ParameterIdentifier(certParameterScope, ParameterType.VERSION));
        }

        return parameterIdentifiers;
    }

    private static Constraint[] getConstraints(List<ParameterIdentifier> parameterIdentifiers,
        DerivationScope derivationScope, TestContext testContext) {
        List<Constraint> constraints = new ArrayList<>();
        for (ParameterIdentifier parameterIdentifier : parameterIdentifiers) {
            DerivationParameter parameter = ParameterFactory.getInstance(parameterIdentifier);
            if (parameter.canBeModeled(testContext, derivationScope)) {
                List<ConditionalConstraint> conditionalConstraints =
                    parameter.getConditionalConstraints(derivationScope);
                for (ConditionalConstraint conditionalConstraint : conditionalConstraints) {
                    if (conditionalConstraint.isApplicableTo(parameterIdentifiers, derivationScope)) {
                        constraints.add(conditionalConstraint.getConstraint());
                    }
                }
            }
        }
        return constraints.toArray(new Constraint[0]);
    }
}
