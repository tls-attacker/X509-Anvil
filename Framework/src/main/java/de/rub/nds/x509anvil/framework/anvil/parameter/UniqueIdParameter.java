/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

public abstract class UniqueIdParameter extends CertificateSpecificParameter<byte[]> {
    private final X509AnvilParameterType uniqueIdPresentParameterType;

    public UniqueIdParameter(
            ParameterIdentifier parameterIdentifier,
            X509AnvilParameterType uniqueIdPresentParameterType) {
        super(parameterIdentifier, byte[].class);
        this.uniqueIdPresentParameterType = uniqueIdPresentParameterType;
    }

    public UniqueIdParameter(
            byte[] selectedValue,
            ParameterIdentifier parameterIdentifier,
            X509AnvilParameterType uniqueIdPresentParameterType) {
        this(parameterIdentifier, uniqueIdPresentParameterType);
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, byte[]>> getNonNullParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, byte[]>> values = new ArrayList<>();
        values.add(generateValue(new byte[0]));
        values.add(generateValue(new byte[] {0x0, 0x1, 0x2, (byte) 0xff}));
        byte[] bytes = new byte[64];
        for (byte b = 0; b < 64; b++) {
            bytes[b] = b;
        }
        values.add(generateValue(bytes));
        return values;
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>>
            getAdditionalEnableConditions() {
        Map<ParameterIdentifier, Predicate<DerivationParameter>> additionalConditions =
                new HashMap<>();
        // Model parameter only if corresponding UniqueIdPresent parameter is true
        additionalConditions.put(
                getScopedIdentifier(uniqueIdPresentParameterType),
                CommonConstraints::enabledByParameterCondition);
        return additionalConditions;
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
