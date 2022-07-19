package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.math.BigInteger;
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
    public List<DerivationParameter> getParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> parameterValues = new ArrayList<>();
        parameterValues.add(generateValue(null)); // If we don't want this parameter to be modelled (i.e. ParameterScope is not in use)
        parameterValues.add(generateValue(false));
        parameterValues.add(generateValue(true));
        return parameterValues;
    }
}
