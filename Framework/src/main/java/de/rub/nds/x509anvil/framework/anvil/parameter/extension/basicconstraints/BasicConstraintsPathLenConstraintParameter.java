/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ConstraintHelper;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.ChainLengthParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.Extension;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class BasicConstraintsPathLenConstraintParameter extends CertificateSpecificParameter<Integer> {

    public BasicConstraintsPathLenConstraintParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT, parameterScope),
            Integer.class);
    }

    public BasicConstraintsPathLenConstraintParameter(Integer selectedValue, ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT, parameterScope),
            Integer.class);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Integer> generateValue(Integer selectedValue) {
        return new BasicConstraintsPathLenConstraintParameter(selectedValue,
            getParameterIdentifier().getParameterScope());
    }

    @Override
    protected List<DerivationParameter<X509CertificateChainConfig, Integer>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, Integer>> derivationParameters = new ArrayList<>();
        // Generate enough pathlen values for maximum chain length
        int maxChainLength = AnnotationUtil.resolveMaxChainLength(derivationScope.getExtensionContext());
        for (int i = 0; i <= maxChainLength - 2; i++) {
            derivationParameters.add(generateValue(i));
        }
        // Add an unreasonably high (but still valid) value
        derivationParameters.add(generateValue(1000));
        return derivationParameters;
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        // BasicConstraintsExtensionConfig extensionConfig =
        //     (BasicConstraintsExtensionConfig) certificateConfig.extension(ExtensionType.BASIC_CONSTRAINTS);
        // extensionConfig.setPathLenConstraint(getSelectedValue());
        certificateConfig.addExtensions((Extension) null);
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        return Collections.singletonMap(
            getScopedIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT),
            CommonConstraints::enabledByParameterCondition);
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);

        // Coffee4j cannot handle constraints without effect. Only add constraint if at least
        // one other intermediate certificate follows in chain
        int maxChainLength = AnnotationUtil.resolveMaxChainLength(derivationScope.getExtensionContext());
        if (getParameterScope().isIntermediate() && getParameterScope().getIntermediateIndex() < maxChainLength - 3) {
            defaultConstraints.add(ValueRestrictionConstraintBuilder
                .<Integer>init("if CA is asserted, pathlen must be big enough (or null)", derivationScope).target(this)
                .requiredParameter(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH))
                // Allow only values that are big enough and null...
                .restrictValues((target, requiredParameters) -> {
                    List<Integer> restrictedValues = new ArrayList<>();
                    restrictedValues.add(null);
                    ChainLengthParameter chainLengthParameter =
                        (ChainLengthParameter) ConstraintHelper.getParameterValue(requiredParameters,
                            new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH));
                    int chainLength = chainLengthParameter.getSelectedValue();
                    int minimumPathLen = chainLength - getParameterScope().getIntermediateIndex() - 3;
                    restrictedValues.addAll(IntStream.range(0, minimumPathLen).boxed().collect(Collectors.toList()));
                    return restrictedValues;
                })
                // ... if the certificate is an intermediate certificate
                .condition((target, requiredParameters) -> {
                    int chainLength = ((ChainLengthParameter) requiredParameters.get(0)).getSelectedValue();
                    return (getParameterScope().getIntermediateIndex() < chainLength - 3); // "is intermediate cert"
                }).get());
        }

        return defaultConstraints;
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}