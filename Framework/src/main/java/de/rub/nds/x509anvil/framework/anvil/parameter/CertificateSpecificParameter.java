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
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.*;
import java.util.function.Predicate;

public abstract class CertificateSpecificParameter<T> extends X509AnvilDerivationParameter<T> {

    public CertificateSpecificParameter(ParameterIdentifier parameterIdentifier, Class<T> valueClass) {
        super(valueClass, parameterIdentifier);
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);
        if (!certificateisAlwaysModeled(derivationScope)) {
            AggregatedEnableConstraint<T> aggregatedEnableConstraint = AggregatedEnableConstraintBuilder.<T>init(derivationScope)
                    .constrain(this)
                    .condition(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH), this::certificateParameterScopeModeled)
                    .conditions(getAdditionalEnableConditions())
                    .defaultValue(getDefaultDisabledValue(derivationScope))
                    .get();
            defaultConstraints.add(aggregatedEnableConstraint);
        }
        else if (canBeDisabled(derivationScope)) {
            AggregatedEnableConstraint<T> aggregatedEnableConstraint = AggregatedEnableConstraintBuilder.<T>init(derivationScope)
                    .constrain(this)
                    .conditions(getAdditionalEnableConditions())
                    .defaultValue(getDefaultDisabledValue(derivationScope))
                    .get();
            defaultConstraints.add(aggregatedEnableConstraint);
        }
        return defaultConstraints;
    }


    @Override
    public void applyToConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {
        if (getSelectedValue() != null && getParameterScope().isModeled(config.getChainLength())) {
            applyToCertificateConfig(getCertificateConfigByScope(config), derivationScope);
        }
    }

    protected abstract void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope);


    @Override
    public List<DerivationParameter> getParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> parameterValues = new ArrayList<>();
        // A value of null (or a default value) is used whenever we don't want to model this parameter at all
        if ((!certificateisAlwaysModeled(derivationScope) || canBeDisabled(derivationScope)) && getDefaultDisabledValue(derivationScope) == null) {
            parameterValues.add(generateValue(null));
        }
        parameterValues.addAll(getNonNullParameterValues(derivationScope));
        return parameterValues;
    }

    protected abstract List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope);

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
        return getParameterScope().isModeled(chainLength);
    }

    protected X509CertificateConfig getCertificateConfigByScope(X509CertificateChainConfig certificateChainConfig) {
        X509AnvilParameterScope parameterScope = getParameterScope();
        if (parameterScope.isRoot()) {
            return certificateChainConfig.getRootCertificateConfig();
        } else if (parameterScope.isEntity()) {
            return certificateChainConfig.getEntityCertificateConfig();
        } else {
            return certificateChainConfig.getIntermediateConfig(parameterScope.getIntermediateIndex());
        }
    }

    public X509AnvilParameterScope getParameterScope() {
        return (X509AnvilParameterScope) getParameterIdentifier().getParameterScope();
    }

    public ParameterIdentifier getScopedIdentifier(X509AnvilParameterType parameterType) {
        return new ParameterIdentifier(parameterType, getParameterIdentifier().getParameterScope());
    }

    /**
     * Returns true if the corresponding certificate is always modeled for the selected minChainLength
     * setting.
     */
    public boolean certificateisAlwaysModeled(DerivationScope derivationScope) {
        int minChainLength = AnnotationUtil.resolveMinChainLength(derivationScope.getExtensionContext());
        return getParameterScope().isModeled(minChainLength);
    }

    // Override when a parameter is en-/disabled with another Boolean parameter
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return false;
    }

    // Override if the disabled state should not be modeled as null
    protected T getDefaultDisabledValue(DerivationScope derivationScope) {
        return null;
    }
}
