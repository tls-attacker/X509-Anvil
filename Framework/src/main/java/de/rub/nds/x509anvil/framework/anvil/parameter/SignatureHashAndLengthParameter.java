/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.key.CachedKeyPairGenerator;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureHashAndLengthParameter
        extends CertificateSpecificParameter<SignatureHashAlgorithmKeyLengthPair> {

    public SignatureHashAndLengthParameter(ParameterScope parameterScope) {
        super(
                new ParameterIdentifier(X509AnvilParameterType.KEY_TYPE, parameterScope),
                SignatureHashAlgorithmKeyLengthPair.class);
    }

    public SignatureHashAndLengthParameter(
            ParameterScope parameterScope, SignatureHashAlgorithmKeyLengthPair value) {
        this(parameterScope);
        setSelectedValue(value);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, SignatureHashAlgorithmKeyLengthPair>
            generateValue(SignatureHashAlgorithmKeyLengthPair selectedValue) {
        return new SignatureHashAndLengthParameter(
                getParameterIdentifier().getParameterScope(), selectedValue);
    }

    @Override
    protected List<
                    DerivationParameter<
                            X509CertificateChainConfig, SignatureHashAlgorithmKeyLengthPair>>
            getNonNullParameterValues(DerivationScope derivationScope) {

        FeatureReport featureReport = ContextHelper.getFeatureReport();
        List<SignatureHashAlgorithmKeyLengthPair> signatureHashAlgorithmKeyLengthPairs;

        int chainLength =
                AnnotationUtil.resolveMinChainLength(derivationScope.getExtensionContext());

        if (getParameterScope().isEntity() && chainLength >= 3) {
            signatureHashAlgorithmKeyLengthPairs =
                    featureReport.getSupportedSignatureHashAndKeyLengthPairsEntity();
            return signatureHashAlgorithmKeyLengthPairs.stream()
                    .map(
                            signatureHashAlgorithmKeyLengthPair ->
                                    new SignatureHashAndLengthParameter(
                                            getParameterScope(),
                                            signatureHashAlgorithmKeyLengthPair))
                    .collect(Collectors.toList());
        } else if (getParameterScope().isIntermediate()
                && getParameterScope().getIntermediateIndex() == 0
                && chainLength >= 4) {
            signatureHashAlgorithmKeyLengthPairs =
                    featureReport.getSupportedSignatureHashAndKeyLengthPairsIntermediate();
            return signatureHashAlgorithmKeyLengthPairs.stream()
                    .map(
                            signatureHashAlgorithmKeyLengthPair ->
                                    new SignatureHashAndLengthParameter(
                                            getParameterScope(),
                                            signatureHashAlgorithmKeyLengthPair))
                    .collect(Collectors.toList());
        }
        return new ArrayList<>();
    }

    private X509CertificateConfig getSignerConfigByScope(
            X509CertificateChainConfig certificateChainConfig) {
        X509AnvilParameterScope parameterScope = getParameterScope();
        if (parameterScope.isRoot()) { // self-signed root
            return certificateChainConfig.getRootCertificateConfig();
        } else if (parameterScope.isEntity()) { // first inter
            return certificateChainConfig.getLastSigningConfig();
        } else { // upper inter or root
            if (parameterScope.getIntermediateIndex() + 1
                    < certificateChainConfig.getIntermediateCertificateConfigs().size()) {
                return certificateChainConfig.getIntermediateConfig(
                        parameterScope.getIntermediateIndex());
            } else {
                return certificateChainConfig.getRootCertificateConfig();
            }
        }
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {
        if (getSelectedValue() != null) {
            if (getParameterScope().isModeled(config.getChainLength() - 1)) {
                applyToCertificateConfig(getCertificateConfigByScope(config), derivationScope);
                applyToSignerConfig(getSignerConfigByScope(config), config);
            } else {
                throw new UnsupportedOperationException(
                        "Signature hash and length algorithm tried to modify root");
            }
        }
    }

    @Override
    protected void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        // set the correct algorithm in cert
        certificateConfig.setSignatureAlgorithm(getSelectedValue().getSignatureAndHashAlgorithm());
    }

    private void applyToSignerConfig(
            X509CertificateConfig signerConfig, X509CertificateChainConfig certificateChainConfig) {
        // set keys in signer config
        CachedKeyPairGenerator.generateNewKeys(
                getSelectedValue(),
                signerConfig,
                getSignerParameterIdentifier(certificateChainConfig));

        // if root keys changed, signature algorithm has to match. Also for self-signed
        X509AnvilParameterScope parameterScope = getParameterScope();
        if (parameterScope.isRoot() || signerConfig.isSelfSigned()) {
            signerConfig.setSignatureAlgorithm(getSelectedValue().getSignatureAndHashAlgorithm());
        } else if (!parameterScope.isEntity()
                && parameterScope.getIntermediateIndex() + 1
                        >= certificateChainConfig.getIntermediateCertificateConfigs().size()) {
            signerConfig.setSignatureAlgorithm(getSelectedValue().getSignatureAndHashAlgorithm());
        }
    }

    private String getSignerParameterIdentifier(X509CertificateChainConfig certificateChainConfig) {
        X509AnvilParameterScope parameterScope = getParameterScope();
        if (parameterScope.isRoot()) { // self-signed root
            return "root";
        } else if (parameterScope.isEntity()) { // first inter
            return "inter0";
        } else { // upper inter or root
            if (parameterScope.getIntermediateIndex() + 1
                    < certificateChainConfig.getIntermediateCertificateConfigs().size()) {
                return "inter" + (parameterScope.getIntermediateIndex() + 1);
            } else {
                return "root";
            }
        }
    }
}
