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
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.DirectoryStringType;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class CNTypeParameter extends CertificateSpecificParameter<DirectoryStringType> {

    public CNTypeParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.CN_TYPE, parameterScope), DirectoryStringType.class);
    }

    public CNTypeParameter(ParameterScope parameterScope, DirectoryStringType selectedValue) {
        super(new ParameterIdentifier(X509AnvilParameterType.CN_TYPE, parameterScope), DirectoryStringType.class);
        setSelectedValue(selectedValue);
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.getSubject().setCn(certificateConfig.getCertificateName(), getSelectedValue());
    }

    @Override
    protected List<DerivationParameter<X509CertificateChainConfig, DirectoryStringType>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        return Arrays.stream(DirectoryStringType.values()).map(this::generateValue).collect(Collectors.toList());
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, DirectoryStringType>
        generateValue(DirectoryStringType selectedValue) {
        return new CNTypeParameter(getParameterScope(), selectedValue);
    }
}
