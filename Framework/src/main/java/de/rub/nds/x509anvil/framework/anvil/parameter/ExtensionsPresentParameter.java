package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.Collections;
import java.util.Map;
import java.util.function.Predicate;

public class ExtensionsPresentParameter extends  BooleanCertificateSpecificParameter {
    // TODO If present, this field is a SEQUENCE of one or more certificate extensions.

    public ExtensionsPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    public ExtensionsPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new ExtensionsPresentParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setExtensionsPresent(getSelectedValue());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Extensions are only allowed in v3 certificates
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.VERSION),
                new CertificateSpecificParameter.AllowParameterValuesCondition<>(2)
        );
    }
}
