package de.rub.nds.x509anvil.framework.anvil.parameter.extension.subjectalternativename;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;

import java.util.Collections;
import java.util.List;

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
        SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
        subjectAlternativeNameConfig.setPresent(getSelectedValue());
        subjectAlternativeNameConfig.setCritical(false);
        subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.RFC822_NAME));
        subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tessa.com"));
        certificateConfig.addExtensions(subjectAlternativeNameConfig);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(
            Boolean selectedValue) {
        return new SubjectAlternativeNamePresentParameter(selectedValue, getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>> getNonNullParameterValues(
            DerivationScope derivationScope) {
        // Do not modify in root TODO: ???
        if (getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(false));
        }
        return super.getNonNullParameterValues(derivationScope);
    }
}
