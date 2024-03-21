/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.name;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.DirectoryStringType;

public class NameComponentPresentParameter extends BooleanCertificateSpecificParameter {
    private final String nameComponentOid;
    private final String value;

    public NameComponentPresentParameter(ParameterIdentifier parameterIdentifier, String nameComponentOid,
        String value) {
        super(parameterIdentifier);
        this.nameComponentOid = nameComponentOid;
        this.value = value;
    }

    public NameComponentPresentParameter(Boolean selectedValue, ParameterIdentifier parameterIdentifier,
        String nameComponentOid, String value) {
        super(selectedValue, parameterIdentifier);
        this.nameComponentOid = nameComponentOid;
        this.value = value;
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        if (getSelectedValue()) {
            certificateConfig.getSubject().addNameComponent(nameComponentOid, value, DirectoryStringType.PRINTABLE);
        }
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new NameComponentPresentParameter(selectedValue, getParameterIdentifier(), nameComponentOid, value);
    }
}
