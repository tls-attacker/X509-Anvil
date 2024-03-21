/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.KeyUsageExtensionConfig;

import java.util.Collections;
import java.util.List;
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
        KeyUsageExtensionConfig extensionConfig =
            (KeyUsageExtensionConfig) certificateConfig.extension(ExtensionType.KEY_USAGE);
        extensionConfig.setFlag(getBitPosition(), getSelectedValue());
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new KeyUsageFlagParameter(selectedValue, getParameterIdentifier(), bitPosition);
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        // Entity certificates may be required to have digitalSignature bit set (e.g. if verifier adapter uses client
        // authentication)
        if (getParameterScope().isEntity() && bitPosition == KeyUsageExtensionConfig.DIGITAL_SIGNATURE) {
            FeatureReport featureReport = ContextHelper.getFeatureReport();
            if (featureReport.isDigitalSignatureKeyUsageRequired()) {
                return Collections.singletonList(generateValue(true));
            }
        }

        // CA certificates are required to assert keyCertSign if key usage extension is present
        if (!getParameterScope().isEntity() && bitPosition == KeyUsageExtensionConfig.KEY_CERT_SIGN) {
            return Collections.singletonList(generateValue(true));
        }

        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Only model if corresponding ExtensionPresent parameter is true
        return Collections.singletonMap(getScopedIdentifier(X509AnvilParameterType.EXT_KEY_USAGE_PRESENT),
            CommonConstraints::enabledByParameterCondition);
    }

    public int getBitPosition() {
        return bitPosition;
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
