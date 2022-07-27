package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.ChainLengthParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.ChainPositionUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

public class BasicConstraintsCaParameter extends BooleanCertificateSpecificParameter {

    public BasicConstraintsCaParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_CA, parameterScope));
    }

    public BasicConstraintsCaParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_CA, parameterScope));
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new BasicConstraintsCaParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        BasicConstraintsExtensionConfig extensionConfig = (BasicConstraintsExtensionConfig) certificateConfig.extension(ExtensionType.BASIC_CONSTRAINTS);
        extensionConfig.setCa(getSelectedValue());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Only model if corresponding ExtensionPresent parameter is true
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT),
                CertificateSpecificParameter::enabledByParameterCondition
        );
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);

        int maxEntityCertChainPosition = AnnotationUtil.resolveMaxEntityCertChainPosition(derivationScope.getExtensionContext());
        if (getChainPosition() > 0 && getChainPosition() < maxEntityCertChainPosition) {
            defaultConstraints.add(0, ValueRestrictionConstraintBuilder.init("intermediate cert must have ca flag asserted", derivationScope)
                    .target(this)
                    .requiredParameter(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH))
                    .allowValues(Collections.singletonList(true))
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
