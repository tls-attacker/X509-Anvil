/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

public class X509VerifierRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private X509CertificateChainConfig preparedConfig;
    private ParameterCombination parameterCombination;
    private final ExtensionContext extensionContext;

    public X509VerifierRunner(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    public X509VerifierRunner(
            ExtensionContext extensionContext, X509CertificateChainConfig config) {
        this(extensionContext);
        this.preparedConfig = config;
    }

    public X509CertificateChainConfig getPreparedConfig() {
        return preparedConfig;
    }

    public void setPreparedConfig(X509CertificateChainConfig preparedConfig) {
        this.preparedConfig = preparedConfig;
    }

    public ParameterCombination getParameterCombination() {
        return parameterCombination;
    }

    public void setParameterCombination(ParameterCombination parameterCombination) {
        this.parameterCombination = parameterCombination;
    }

    public VerifierResult execute(X509CertificateChainConfig config)
            throws CertificateGeneratorException, VerifierException {
        X509CertificateChainGenerator certificateChainGenerator =
                new X509CertificateChainGenerator(config);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateList =
                certificateChainGenerator.retrieveCertificateChain();

        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter =
                VerifierAdapterFactory.getInstance(
                        testConfig.getVerifierAdapterType(), testConfig.getVerifierAdapterConfig());
        return verifierAdapter.invokeVerifier(config.getEntityCertificateConfig(), certificateList);
    }

    // TODO: modifiers unset rn, switch all tests to new modifiers
    public VerifierResult execute(
            X509CertificateChainConfig config, X509CertificateConfigModifier modifier)
            throws CertificateGeneratorException, VerifierException {
        X509CertificateChainGenerator certificateChainGenerator =
                new X509CertificateChainGenerator(config);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateList =
                certificateChainGenerator.retrieveCertificateChain();
        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter =
                VerifierAdapterFactory.getInstance(
                        testConfig.getVerifierAdapterType(), testConfig.getVerifierAdapterConfig());
        return verifierAdapter.invokeVerifier(config.getEntityCertificateConfig(), certificateList);
    }

    public VerifierResult execute(
            X509CertificateConfig leafCertificateConfig, List<X509Certificate> certificateList)
            throws VerifierException {

        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter =
                VerifierAdapterFactory.getInstance(
                        testConfig.getVerifierAdapterType(), testConfig.getVerifierAdapterConfig());
        return verifierAdapter.invokeVerifier(leafCertificateConfig, certificateList);
    }
}
