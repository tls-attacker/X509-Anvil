package de.rub.nds.x509anvil.framework.anvil.parameter.extension.subjectalternativename;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class SubjectAlternativeNamePresentParameter extends ExtensionPresentParameter {
    public SubjectAlternativeNamePresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_SUBJECT_ALT_NAME_PRESENT, parameterScope));
    }

    public SubjectAlternativeNamePresentParameter(Boolean selectedValue, ParameterScope parameterScope){
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXT_SUBJECT_ALT_NAME_PRESENT, parameterScope));
    }

    @Override
    public void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        Optional<ExtensionConfig> config = certificateConfig.getExtensions().stream().filter(e -> Objects.equals(e.getExtensionId(), X509ExtensionType.SUBJECT_ALTERNATIVE_NAME.getOid())).findFirst();
        if (config.isPresent()) {
            config.get().setPresent(getSelectedValue());
        } else {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(getSelectedValue());
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            certificateConfig.addExtensions(subjectAlternativeNameConfig);
        }
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(
            Boolean selectedValue) {
        return new SubjectAlternativeNamePresentParameter(selectedValue, getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>> getNonNullParameterValues(
            DerivationScope derivationScope) {
        if (getParameterScope().isRoot()) {
            return Collections.singletonList(generateValue(false));
        }
        return super.getNonNullParameterValues(derivationScope);
    }
}
