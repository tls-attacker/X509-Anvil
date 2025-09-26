package de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

public class KeyUsageAdditionalUsagesParameter extends CertificateSpecificParameter<boolean[]> {
    public KeyUsageAdditionalUsagesParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_KEY_USAGE_ADDITIONAL, parameterScope), boolean[].class);
    }

    public KeyUsageAdditionalUsagesParameter(boolean[] selectedValue,  ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        KeyUsageConfig keyUsageConfig =
                (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(
                        certificateConfig, X509ExtensionType.KEY_USAGE);
        keyUsageConfig.setKeyCertSign(getSelectedValue()[0]);
        keyUsageConfig.setDigitalSignature(getSelectedValue()[1]);
        keyUsageConfig.setcRLSign(getSelectedValue()[2]);
        keyUsageConfig.setKeyAgreement(getSelectedValue()[3]);
        keyUsageConfig.setKeyEncipherment(getSelectedValue()[4]);
        keyUsageConfig.setNonRepudiation(getSelectedValue()[5]);
        keyUsageConfig.setDataEncipherment(getSelectedValue()[6]);
        keyUsageConfig.setDecipherOnly(getSelectedValue()[7]);
        keyUsageConfig.setEncipherOnly(getSelectedValue()[8]);
    }

    @Override
    protected List<DerivationParameter<X509CertificateChainConfig, boolean[]>> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, boolean[]>> parameterValues = new ArrayList<>();
        if (getParameterScope().isEntity()) {
            parameterValues.add(generateValue(new boolean[]{true, true, false, true, true, false, false, false, false}));
            parameterValues.add(generateValue(new boolean[]{false, true, true, true, true, false, false, false, false}));
            parameterValues.add(generateValue(new boolean[]{false, true, false, true, true, true, false, false, false}));
            parameterValues.add(generateValue(new boolean[]{false, true, false, true, true, false, true, false, false}));
            parameterValues.add(generateValue(new boolean[]{false, true, false, true, true, false, false, true, false}));
            parameterValues.add(generateValue(new boolean[]{false, true, false, true, true, false, false, false, true}));
        } else {
            parameterValues.add(generateValue(new boolean[]{true, true, true, true, false, false, false, false, false}));
            parameterValues.add(generateValue(new boolean[]{true, true, true, false, true, false, false, false, false}));
            parameterValues.add(generateValue(new boolean[]{true, true, true, false, false, true, false, false, false}));
            parameterValues.add(generateValue(new boolean[]{true, true, true, false, false, false, true, false, false}));
            parameterValues.add(generateValue(new boolean[]{true, true, true, false, false, false, false, true, false}));
            parameterValues.add(generateValue(new boolean[]{true, true, true, false, false, false, false, false, true}));
        }
        return parameterValues;
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, boolean[]> generateValue(boolean[] selectedValue) {
        return new KeyUsageAdditionalUsagesParameter(selectedValue,  getParameterScope());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>>
    getAdditionalEnableConditions() {
        // Don't model extension if extensions sequence is not present
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT),
                CommonConstraints::enabledByParameterCondition);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
