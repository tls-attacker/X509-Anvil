package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.util.Collections;
import java.util.Map;
import java.util.function.Predicate;

public class IssuerUniqueIdPresentParameter extends BooleanCertificateSpecificParameter {

    public IssuerUniqueIdPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.ISSUER_UNIQUE_ID_PRESENT, parameterScope));
    }

    public IssuerUniqueIdPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.ISSUER_UNIQUE_ID_PRESENT, parameterScope));
    }

    @Override
    public DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new IssuerUniqueIdPresentParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {
        if (getSelectedValue() != null) {
            getCertificateConfigByScope(config).setIssuerUniqueIdPresent(getSelectedValue());
        }
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.VERSION),
                new CertificateSpecificParameter.AllowParameterValuesCondition<>(2)
        );
    }
}
