/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithmLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.security.KeyPair;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureParameter extends CertificateSpecificParameter<SignatureAlgorithmLengthPair> {

    public SignatureParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.KEY_TYPE, parameterScope), SignatureAlgorithmLengthPair.class);
    }

    public SignatureParameter(ParameterScope parameterScope, SignatureAlgorithmLengthPair value) {
        this(parameterScope);
        setSelectedValue(value);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, SignatureAlgorithmLengthPair>
        generateValue(SignatureAlgorithmLengthPair selectedValue) {
        return new SignatureParameter(getParameterIdentifier().getParameterScope(), selectedValue);
    }

    @Override
    protected List<DerivationParameter<X509CertificateChainConfig, SignatureAlgorithmLengthPair>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        FeatureReport featureReport = ContextHelper.getFeatureReport();
        List<SignatureAlgorithmLengthPair> supportedKeyLength;
        if (getParameterScope().isEntity()) {
            supportedKeyLength = featureReport.getSupportedEntityKeyLengths();
        } else {
            supportedKeyLength = featureReport.getSupportedKeyLengths();
        }
        return supportedKeyLength.stream().map(this::generateValue).collect(Collectors.toList());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.amendSignatureAlgorithm(getSelectedValue().getSignatureAlgorithm());
        KeyPair keyPair = X509CertificateConfigUtil.generateKeyPair(getSelectedValue().getSignatureAlgorithm(),
            certificateConfig.getCertificateName(), getSelectedValue().getKeyLength());
        certificateConfig.applyKeyPair(keyPair);
    }
}
