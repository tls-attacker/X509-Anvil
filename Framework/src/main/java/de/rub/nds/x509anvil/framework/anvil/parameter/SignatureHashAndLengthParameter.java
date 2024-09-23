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
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.x509.config.CachedKeyPairGenerator;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;

import java.util.List;
import java.util.stream.Collectors;

public class SignatureHashAndLengthParameter extends CertificateSpecificParameter<SignatureHashAlgorithmKeyLengthPair> {

    public SignatureHashAndLengthParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.KEY_TYPE, parameterScope),
                SignatureHashAlgorithmKeyLengthPair.class);
    }

    public SignatureHashAndLengthParameter(ParameterScope parameterScope, SignatureHashAlgorithmKeyLengthPair value) {
        this(parameterScope);
        setSelectedValue(value);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, SignatureHashAlgorithmKeyLengthPair>
        generateValue(SignatureHashAlgorithmKeyLengthPair selectedValue) {
        return new SignatureHashAndLengthParameter(getParameterIdentifier().getParameterScope(), selectedValue);
    }

    @Override
    protected List<DerivationParameter<X509CertificateChainConfig, SignatureHashAlgorithmKeyLengthPair>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        FeatureReport featureReport = ContextHelper.getFeatureReport();
        List<SignatureHashAlgorithmKeyLengthPair> signatureHashAlgorithmKeyLengthPairs;
        if (getParameterScope().isEntity()) {
            signatureHashAlgorithmKeyLengthPairs = featureReport.getSupportedSignatureHashAndKeyLengthPairsEntity();
        } else {
            signatureHashAlgorithmKeyLengthPairs = featureReport.getSupportedSignatureHashAndKeyLengthPairsIntermediate();
        }
        return signatureHashAlgorithmKeyLengthPairs.stream().map(this::generateValue).collect(Collectors.toList());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setSignatureAlgorithm(getSelectedValue().getSignatureAndHashAlgorithm());
        CachedKeyPairGenerator.generateNewKeys(getSelectedValue(), certificateConfig);
    }
}
