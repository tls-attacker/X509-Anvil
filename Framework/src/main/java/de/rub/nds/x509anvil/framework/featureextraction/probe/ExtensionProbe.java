/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ExtensionProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.List;

public abstract class ExtensionProbe implements Probe {
    private final ExtensionType extensionType;

    protected ExtensionProbe(ExtensionType extensionType) {
        this.extensionType = extensionType;
    }

    @Override
    public ProbeResult execute() throws ProbeException {
        try {
            X509CertificateChainConfig baseConfig = prepareBaseConfig();
            if (!testCertificateChain(baseConfig)) {
                throw new ProbeException("Base config is already invalid");
            }
            addExtensionToConfig(baseConfig);
            boolean resultValid = testCertificateChain(baseConfig);
            // FIXME
            // boolean resultInvalid = testCertificateChain(baseConfig,
            // createInvalidExtensionModifier());
            // return new ExtensionProbeResult(extensionType, resultValid && !resultInvalid);
            return new ExtensionProbeResult(extensionType, resultValid);
        } catch (VerifierException | CertificateGeneratorException e) {
            throw new ProbeException("Unable to execute probe", e);
        }
    }

    protected abstract X509CertificateChainConfig prepareBaseConfig();

    protected abstract void addExtensionToConfig(X509CertificateChainConfig config);

    protected boolean testCertificateChain(X509CertificateChainConfig config)
            throws CertificateGeneratorException, VerifierException {
        X509CertificateChainGenerator certificateChainGenerator =
                new X509CertificateChainGenerator(config);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateChain =
                certificateChainGenerator.retrieveCertificateChain();

        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter =
                VerifierAdapterFactory.getInstance(
                        testConfig.getVerifierAdapterType(), testConfig.getVerifierAdapterConfig());
        VerifierResult verifierResult =
                verifierAdapter.invokeVerifier(
                        config.getEntityCertificateConfig(), certificateChain);
        return verifierResult.isValid();
    }
}
