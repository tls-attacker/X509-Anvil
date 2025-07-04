/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.name;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;

/** Adds a certain Name Component to the Subject. */
public class NameComponentPresentParameter extends BooleanCertificateSpecificParameter {
    private final X500AttributeType nameComponent;
    private final String value;

    public NameComponentPresentParameter(
            ParameterIdentifier parameterIdentifier,
            X500AttributeType nameComponent,
            String value) {
        super(parameterIdentifier);
        this.nameComponent = nameComponent;
        this.value = value;
    }

    public NameComponentPresentParameter(
            Boolean selectedValue,
            ParameterIdentifier parameterIdentifier,
            X500AttributeType nameComponent,
            String value) {
        super(selectedValue, parameterIdentifier);
        this.nameComponent = nameComponent;
        this.value = value;
    }

    @Override
    protected void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        if (getSelectedValue()) {
            certificateConfig.getSubject().add(new Pair<>(nameComponent, value));
        }
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(
            Boolean selectedValue) {
        return new NameComponentPresentParameter(
                selectedValue, getParameterIdentifier(), nameComponent, value);
    }
}
