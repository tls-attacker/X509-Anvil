package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

public class BasicConstraintsPathLenConstraint extends CertificateSpecificParameter<Integer> {

    public BasicConstraintsPathLenConstraint(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT, parameterScope), Integer.class);
    }

    public BasicConstraintsPathLenConstraint(Integer selectedValue, ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT, parameterScope), Integer.class);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Integer> generateValue(Integer selectedValue) {
        return new BasicConstraintsPathLenConstraint(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    protected List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> derivationParameters = new ArrayList<>();
        // Generate enough pathlen values for maximum chain length
        ChainLength chainLengthAnnotation = AnnotationUtil.resolveChainLengthAnnotation(derivationScope.getExtensionContext());
        int maxChainLength = AnnotationUtil.resolveMaxLength(chainLengthAnnotation);
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
}