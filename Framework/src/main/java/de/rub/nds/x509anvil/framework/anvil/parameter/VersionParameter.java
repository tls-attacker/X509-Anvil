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
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VersionParameter extends CertificateSpecificParameter<Integer> {

    public VersionParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.VERSION, parameterScope), Integer.class);
    }

    public VersionParameter(Integer selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    public DerivationParameter<X509CertificateChainConfig, Integer> generateValue(Integer selectedValue) {
        return new VersionParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> parameterValues = new ArrayList<>();
        parameterValues.add(generateValue(0)); // Version 1
        parameterValues.add(generateValue(1)); // Version 2
        parameterValues.add(generateValue(2)); // Version 3

        return parameterValues;
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setVersion(BigInteger.valueOf(getSelectedValue()));
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);

        // Coffee4j does not allow constraints that do not constraint any combination. TODO: Fix coffee4j?
        int maxEntityCertChainPosition = AnnotationUtil.resolveMaxEntityCertChainPosition(derivationScope.getExtensionContext());
        if (getChainPosition() > 0 && getChainPosition() < maxEntityCertChainPosition) {
            defaultConstraints.add(0, ValueRestrictionConstraintBuilder.init("intermediate cert must be v3", derivationScope)
                    .target(this)
                    .requiredParameter(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH))
                    .allowValues(Collections.singletonList(2))
                    .condition((target, requiredParameters) -> {
                        int chainLength = ((ChainLengthParameter) requiredParameters.get(0)).getSelectedValue();
                        return ChainPositionUtil.isIntermediate(getChainPosition(), chainLength, derivationScope);
                    })
                    .get()
            );
        }

        return defaultConstraints;
    }
}
