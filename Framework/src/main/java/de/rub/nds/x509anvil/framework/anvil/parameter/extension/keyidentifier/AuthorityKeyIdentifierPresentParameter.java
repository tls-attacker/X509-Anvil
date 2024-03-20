/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyidentifier;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.util.Collections;
import java.util.List;

public class AuthorityKeyIdentifierPresentParameter extends ExtensionPresentParameter {

    public AuthorityKeyIdentifierPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_AUTHORITY_KEY_IDENTIFIER_PRESENT, parameterScope),
            ExtensionType.AUTHORITY_KEY_IDENTIFIER);
    }

    public AuthorityKeyIdentifierPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue,
            new ParameterIdentifier(X509AnvilParameterType.EXT_AUTHORITY_KEY_IDENTIFIER_PRESENT, parameterScope),
            ExtensionType.AUTHORITY_KEY_IDENTIFIER);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new AuthorityKeyIdentifierPresentParameter(selectedValue, getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>> getNonNullParameterValues(DerivationScope derivationScope) {
        if (getParameterScope().isRoot()) {
            return Collections.singletonList(generateValue(false));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
