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
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/** Sets the DirectoryStringType of the subject */
public class CNTypeParameter extends CertificateSpecificParameter<DirectoryStringChoiceType> {

    public CNTypeParameter(ParameterScope parameterScope) {
        super(
                new ParameterIdentifier(X509AnvilParameterType.CN_TYPE, parameterScope),
                DirectoryStringChoiceType.class);
    }

    public CNTypeParameter(ParameterScope parameterScope, DirectoryStringChoiceType selectedValue) {
        super(
                new ParameterIdentifier(X509AnvilParameterType.CN_TYPE, parameterScope),
                DirectoryStringChoiceType.class);
        setSelectedValue(selectedValue);
    }

    @Override
    protected void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setDefaultDirectoryStringType(getSelectedValue());
    }

    @Override
    protected List<DerivationParameter<X509CertificateChainConfig, DirectoryStringChoiceType>>
            getNonNullParameterValues(DerivationScope derivationScope) {
        return Arrays.stream(DirectoryStringChoiceType.values())
                .map(this::generateValue)
                .collect(Collectors.toList());
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, DirectoryStringChoiceType>
            generateValue(DirectoryStringChoiceType selectedValue) {
        return new CNTypeParameter(getParameterScope(), selectedValue);
    }
}
