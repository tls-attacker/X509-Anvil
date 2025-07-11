/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.extension;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import java.util.Collections;
import java.util.Map;
import java.util.function.Predicate;

public class ExtensionPresentParameter extends BooleanCertificateSpecificParameter {
    private final ExtensionType extensionType;

    public ExtensionPresentParameter(
            ParameterIdentifier parameterIdentifier, ExtensionType extensionType) {
        super(parameterIdentifier);
        this.extensionType = extensionType;
    }

    public ExtensionPresentParameter(
            Boolean selectedValue,
            ParameterIdentifier parameterIdentifier,
            ExtensionType extensionType) {
        super(selectedValue, parameterIdentifier);
        this.extensionType = extensionType;
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(
            Boolean selectedValue) {
        return new ExtensionPresentParameter(
                selectedValue, getParameterIdentifier(), extensionType);
    }

    @Override
    public void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        ExtensionConfig config =
                X509CertificateConfigUtil.getExtensionConfig(
                        certificateConfig, X509ExtensionType.BASIC_CONSTRAINTS);
        config.setPresent(getSelectedValue());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>>
            getAdditionalEnableConditions() {
        // Don't model extension if extensions sequence is not present
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT),
                CommonConstraints::enabledByParameterCondition);
    }

    public ExtensionType getExtensionType() {
        return extensionType;
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
