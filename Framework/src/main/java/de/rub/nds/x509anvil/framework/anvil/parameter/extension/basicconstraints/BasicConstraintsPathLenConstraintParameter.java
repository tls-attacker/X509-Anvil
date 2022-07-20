package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ConstraintHelper;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.ChainLengthParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.ChainPositionUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class BasicConstraintsPathLenConstraintParameter extends CertificateSpecificParameter<Integer> {

    public BasicConstraintsPathLenConstraintParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT, parameterScope), Integer.class);
    }

    public BasicConstraintsPathLenConstraintParameter(Integer selectedValue, ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT, parameterScope), Integer.class);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Integer> generateValue(Integer selectedValue) {
        return new BasicConstraintsPathLenConstraintParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    protected List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> derivationParameters = new ArrayList<>();
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
        BasicConstraintsExtensionConfig extensionConfig = (BasicConstraintsExtensionConfig) certificateConfig.extension(ExtensionType.BASIC_CONSTRAINTS);
        extensionConfig.setPathLenConstraint(getSelectedValue());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT),
                CertificateSpecificParameter::enabledByParameterCondition
        );
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);

        // Coffee4j cannot handle constraints without effect. Only add constraint if at least
        // one other intermediate certificate follows in chain
        int maxEntityCertChainPosition = AnnotationUtil.resolveMaxEntityCertChainPosition(derivationScope.getExtensionContext());
        int maxChainLength = AnnotationUtil.resolveMaxChainLength(derivationScope.getExtensionContext());
        if (getChainPosition() < maxChainLength - 2 && getChainPosition() != maxEntityCertChainPosition) {
            defaultConstraints.add(0, ValueRestrictionConstraintBuilder.init("if CA is asserted, pathlen must be big enough (or null)", derivationScope)
                    .target(this)
                    .requiredParameter(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH))
                    // Allow only values that are big enough and null...
                    .restrictValues((target, requiredParameters) -> {
                        ChainLengthParameter chainLengthParameter = (ChainLengthParameter)
                                ConstraintHelper.getParameterValues(requiredParameters, new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH));
                        int chainLength = chainLengthParameter.getSelectedValue();
                        int minimumPathLen = chainLength - getChainPosition() - 2;
                        return IntStream.range(0, minimumPathLen).boxed().collect(Collectors.toList());
                    })
                    // ... if the certificate is an intermediate certificate
                    .condition((target, requiredParameters) -> {
                        int chainLength = ((ChainLengthParameter) requiredParameters.get(0)).getSelectedValue();
                        return (getChainPosition() < chainLength - 2 && !ChainPositionUtil.isEntity(getChainPosition(), chainLength, derivationScope));        // "is intermediate cert"
                    })
                    .get()
            );
        }

        return defaultConstraints;
    }
}