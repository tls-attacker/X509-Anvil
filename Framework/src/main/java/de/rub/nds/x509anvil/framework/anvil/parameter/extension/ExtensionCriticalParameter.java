package de.rub.nds.x509anvil.framework.anvil.parameter.extension;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.Collections;
import java.util.Map;
import java.util.function.Predicate;

public class ExtensionCriticalParameter extends BooleanCertificateSpecificParameter {
    private final ExtensionType extensionType;
    private final X509AnvilParameterType extensionPresentType;

    public ExtensionCriticalParameter(ParameterIdentifier parameterIdentifier, ExtensionType extensionType, X509AnvilParameterType extensionPresentType) {
        super(parameterIdentifier);
        this.extensionType = extensionType;
        this.extensionPresentType = extensionPresentType;
    }

    public ExtensionCriticalParameter(Boolean selectedValue, ParameterIdentifier parameterIdentifier, ExtensionType extensionType, X509AnvilParameterType extensionPresentType) {
        super(selectedValue, parameterIdentifier);
        this.extensionType = extensionType;
        this.extensionPresentType = extensionPresentType;
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new ExtensionCriticalParameter(selectedValue, getParameterIdentifier(), extensionType, extensionPresentType);
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.extension(extensionType).setCritical(getSelectedValue());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Only model if corresponding ExtensionPresent parameter is true
        return Collections.singletonMap(
                getScopedIdentifier(extensionPresentType),
                CommonConstraints::enabledByParameterCondition
        );
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
