package de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.Collections;
import java.util.Map;
import java.util.function.Predicate;

public class KeyUsageFlagParameter extends BooleanCertificateSpecificParameter {
    private final int bitPosition;

    public KeyUsageFlagParameter(ParameterIdentifier parameterIdentifier, int bitPosition) {
        super(parameterIdentifier);
        this.bitPosition = bitPosition;
    }

    public KeyUsageFlagParameter(Boolean selectedValue, ParameterIdentifier parameterIdentifier, int bitPosition) {
        super(selectedValue, parameterIdentifier);
        this.bitPosition = bitPosition;
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {

    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new KeyUsageFlagParameter(selectedValue, getParameterIdentifier(), bitPosition);
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Only model if corresponding ExtensionPresent parameter is true
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.EXT_KEY_USAGE_PRESENT),
                CertificateSpecificParameter::enabledByParameterCondition
        );
    }

    public int getBitPosition() {
        return bitPosition;
    }
}
