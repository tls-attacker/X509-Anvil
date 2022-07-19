/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.AggregatedEnableConstraint;
import de.rub.nds.anvilcore.model.constraint.AggregatedEnableConstraintBuilder;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterFactory;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

public abstract class CertificateSpecificParameter<T> extends X509AnvilDerivationParameter<T> {

    public CertificateSpecificParameter(ParameterIdentifier parameterIdentifier, Class<T> valueClass) {
        super(valueClass, parameterIdentifier);
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);
        defaultConstraints.add(createAggregatedEnableConstraint(derivationScope));
        return defaultConstraints;
    }

    private AggregatedEnableConstraint createAggregatedEnableConstraint(DerivationScope derivationScope) {
        return AggregatedEnableConstraintBuilder.init(derivationScope)
                .constrain(this)
                .condition(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH), this::certificateParameterScopeModeled)
                .conditions(getAdditionalEnableConditions())
                .get();
    }

    /**
     * Override method to add additional enable conditions
     */
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        return Collections.emptyMap();
    }

    private boolean certificateParameterScopeModeled(DerivationParameter chainLengthParameter) {
        if (!(chainLengthParameter instanceof ChainLengthParameter)) {
            throw new IllegalArgumentException("Unexpected parameter type, expected ChainLengthParameter");
        }
        Integer chainLength = ((ChainLengthParameter) chainLengthParameter).getSelectedValue();
        return getChainPosition() < chainLength;
    }

    /**
     * This condition predicate can be used whenever a parameter is enabled by another Boolean parameter
     */
    protected static boolean enabledByParameterCondition(DerivationParameter enabler) {
        if (!(enabler instanceof BooleanCertificateSpecificParameter)) {
            throw new IllegalArgumentException("Unexpected parameter type, expected BooleanCertificateSpecificParameter");
        }
        return ((BooleanCertificateSpecificParameter) enabler).getSelectedValue();
    }

    protected X509CertificateConfig getCertificateConfigByScope(X509CertificateChainConfig certificateChainConfig) {
        X509AnvilParameterScope parameterScope = (X509AnvilParameterScope) getParameterIdentifier().getParameterScope();
        return certificateChainConfig.getConfigByChainPosition(parameterScope.getChainPosition());
    }

    public int getChainPosition() {
        return ((X509AnvilParameterScope) getParameterIdentifier().getParameterScope()).getChainPosition();
    }

    public ParameterIdentifier getScopedIdentifier(X509AnvilParameterType parameterType) {
        return new ParameterIdentifier(parameterType, getParameterIdentifier().getParameterScope());
    }
}
