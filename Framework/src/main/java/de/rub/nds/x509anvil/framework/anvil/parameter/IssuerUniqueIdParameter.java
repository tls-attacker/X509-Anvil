package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.BitString;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

public class IssuerUniqueIdParameter extends CertificateSpecificParameter<BitString>{

    public IssuerUniqueIdParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.ISSUER_UNIQUE_ID, parameterScope), BitString.class);
    }

    public IssuerUniqueIdParameter(BitString selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, BitString> generateValue(BitString selectedValue) {
        return new IssuerUniqueIdParameter(selectedValue, this.getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter> getParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter> values = new ArrayList<>();
        values.add(generateValue(null));
        values.add(generateValue(new BitString(new byte[]{0x0,0x1,0x2,(byte)0xff}, 3)));
        byte[] bytes = new byte[64];
        for (byte b = 0; b < 64; b++) {
            bytes[b] = b;
        }
        values.add(generateValue(new BitString(bytes)));
        return values;
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {
        if (getSelectedValue() != null) {
            getCertificateConfigByScope(config).setIssuerUniqueId(getSelectedValue());
        }
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        Map<ParameterIdentifier, Predicate<DerivationParameter>> additionalConditions = new HashMap<>();
        additionalConditions.put(
                getScopedIdentifier(X509AnvilParameterType.ISSUER_UNIQUE_ID_PRESENT),
                CertificateSpecificParameter::enabledByParameterCondition
        );
        additionalConditions.put(
                getScopedIdentifier(X509AnvilParameterType.VERSION),
                new CertificateSpecificParameter.AllowParameterValuesCondition<>(2)
        );
        return additionalConditions;
    }


}
