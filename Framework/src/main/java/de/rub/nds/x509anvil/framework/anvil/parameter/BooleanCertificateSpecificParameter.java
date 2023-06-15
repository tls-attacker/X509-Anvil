/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;

import java.util.ArrayList;
import java.util.List;

public abstract class BooleanCertificateSpecificParameter extends CertificateSpecificParameter<Boolean> {

    public BooleanCertificateSpecificParameter(ParameterIdentifier parameterIdentifier) {
        super(parameterIdentifier, Boolean.class);
    }

    public BooleanCertificateSpecificParameter(Boolean selectedValue, ParameterIdentifier parameterIdentifier) {
        this(parameterIdentifier);
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> parameterValues = new ArrayList<>();
        parameterValues.add(generateValue(false));
        parameterValues.add(generateValue(true));
        return parameterValues;
    }
}
