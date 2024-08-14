/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.extension;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.UnknownConfig;
import de.rub.nds.x509attacker.x509.model.Extension;

import java.util.Collections;
import java.util.Map;
import java.util.function.Predicate;

public class UnknownNonCriticalExtensionPresentParameter extends BooleanCertificateSpecificParameter {

    public UnknownNonCriticalExtensionPresentParameter(ParameterScope parameterScope) {
        super(
            new ParameterIdentifier(X509AnvilParameterType.EXT_UNKNOWN_NONCRITICAL_EXTENSION_PRESENT, parameterScope));
    }

    public UnknownNonCriticalExtensionPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue,
            new ParameterIdentifier(X509AnvilParameterType.EXT_UNKNOWN_NONCRITICAL_EXTENSION_PRESENT, parameterScope));
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new UnknownNonCriticalExtensionPresentParameter(selectedValue,
            getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        UnknownConfig config = new UnknownConfig(new ObjectIdentifier("1.2.3.4.5.6.7"), "unknown");
        config.setCritical(false);
        config.setPresent(true);
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Don't model extension if extensions sequence is not present
        return Collections.singletonMap(getScopedIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT),
            CommonConstraints::enabledByParameterCondition);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
