/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ModelBasedIpmFactory;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;

import java.util.ArrayList;
import java.util.List;

public class X509AnvilModelBasedIpmFactory extends ModelBasedIpmFactory {
    @Override
    protected List<ParameterIdentifier> getAllParameterIdentifiers(DerivationScope derivationScope) {
        List<ParameterIdentifier> parameterIdentifiers = new ArrayList<>();
        parameterIdentifiers.add(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH, X509AnvilParameterScope.GLOBAL));
        parameterIdentifiers.add(new ParameterIdentifier(X509AnvilParameterType.VERSION, X509AnvilParameterScope.CERT_ENTITY));
        parameterIdentifiers.add(new ParameterIdentifier(X509AnvilParameterType.VERSION, X509AnvilParameterScope.CERT_INTERMEDIATE));
        return parameterIdentifiers;
    }
}
