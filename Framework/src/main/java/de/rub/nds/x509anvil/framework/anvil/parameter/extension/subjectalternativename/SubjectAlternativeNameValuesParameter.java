package de.rub.nds.x509anvil.framework.anvil.parameter.extension.subjectalternativename;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

import java.util.*;
import java.util.function.Predicate;

public class SubjectAlternativeNameValuesParameter extends CertificateSpecificParameter<SubjectAlternativeNameTypes> {
    public SubjectAlternativeNameValuesParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_SUBJECT_ALT_NAME_VALUES, parameterScope), SubjectAlternativeNameTypes.class);
    }

    public SubjectAlternativeNameValuesParameter(SubjectAlternativeNameTypes selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        Optional<ExtensionConfig> config = certificateConfig.getExtensions().stream().filter(e -> Objects.equals(e.getExtensionId(), X509ExtensionType.SUBJECT_ALTERNATIVE_NAME.getOid())).findFirst();
        if (config.isPresent()) {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = (SubjectAlternativeNameConfig) config.get();
            switch (getSelectedValue()) {
                case IP -> {
                    subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
                    Asn1OctetString ip = new Asn1OctetString("ip");
                    ip.setValue(new byte[] {(byte) 0xc0, (byte) 0xa8, (byte) 0x00, (byte) 0x01});
                    subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(ip));
                }
                case DNS ->  {
                    subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
                    subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("www.test.com"));
                }
            }
        } else {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            switch (getSelectedValue()) {
                case IP -> {
                    // TODO: IP
                    subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
                    subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("www.test.com"));
                }
                case DNS ->  {
                    subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
                    subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("www.test.com"));
                }
            }
            certificateConfig.addExtensions(subjectAlternativeNameConfig);
        }
    }

    @Override
    protected List<DerivationParameter<X509CertificateChainConfig, SubjectAlternativeNameTypes>> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, SubjectAlternativeNameTypes>> parameterValues = new ArrayList<>();
        for (SubjectAlternativeNameTypes type : SubjectAlternativeNameTypes.values()) {
            parameterValues.add(generateValue(type));
        }
        return parameterValues;
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, SubjectAlternativeNameTypes> generateValue(SubjectAlternativeNameTypes selectedValue) {
        return new SubjectAlternativeNameValuesParameter(selectedValue, getParameterScope());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>>
    getAdditionalEnableConditions() {
        // Only model if corresponding ExtensionPresent parameter is true
        return Collections.singletonMap(
                getScopedIdentifier(X509AnvilParameterType.EXT_SUBJECT_ALT_NAME_PRESENT),
                CommonConstraints::enabledByParameterCondition);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
