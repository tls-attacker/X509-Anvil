package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import org.checkerframework.checker.units.qual.K;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class KeyTypeParameter extends CertificateSpecificParameter<KeyType> {

    public KeyTypeParameter(ParameterScope parameterScope) {
        super (new ParameterIdentifier(X509AnvilParameterType.KEY_TYPE, parameterScope), KeyType.class);
    }

    public KeyTypeParameter(ParameterScope parameterScope, KeyType value) {
        this(parameterScope);
        setSelectedValue(value);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, KeyType> generateValue(KeyType selectedValue) {
        return new KeyTypeParameter(getParameterIdentifier().getParameterScope(), selectedValue);
    }

    @Override
    protected List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        return Arrays.stream(KeyType.values()).map(this::generateValue).collect(Collectors.toList());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {

    }
}
