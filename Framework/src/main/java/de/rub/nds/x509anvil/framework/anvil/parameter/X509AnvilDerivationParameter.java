package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

public abstract class X509AnvilDerivationParameter<T> extends DerivationParameter<X509CertificateChainConfig, T> {

    public X509AnvilDerivationParameter(Class<T> valueClass, ParameterIdentifier parameterIdentifier) {
        super(valueClass, X509CertificateChainConfig.class, parameterIdentifier);
    }
}
