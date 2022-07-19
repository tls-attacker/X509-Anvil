package de.rub.nds.x509anvil.framework.anvil.parameter.extension;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.ExtensionsPresentParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionType;

import java.util.Collections;
import java.util.Map;
import java.util.function.Predicate;

public class ExtensionPresentParameter extends BooleanCertificateSpecificParameter {
    private final ExtensionType extensionType;

    public ExtensionPresentParameter(ParameterIdentifier parameterIdentifier, ExtensionType extensionType) {
        super(parameterIdentifier);
        this.extensionType = extensionType;
    }

    public ExtensionPresentParameter(Boolean selectedValue, ParameterIdentifier parameterIdentifier, ExtensionType extensionType) {
        super(selectedValue, parameterIdentifier);
        this.extensionType = extensionType;
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new ExtensionPresentParameter(selectedValue, getParameterIdentifier(), extensionType);
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.extension(extensionType).setPresent(getSelectedValue());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Don't model extension if extensions sequence is not present
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT),
                CertificateSpecificParameter::enabledByParameterCondition
        );
    }
}
