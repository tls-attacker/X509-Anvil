/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.DigitalSignatureKeyUsageRequiredProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import java.util.List;

public class DigitalSignatureKeyUsageRequired implements Probe {
    @Override
    public ProbeResult execute() throws ProbeException {
        try {
            boolean without = probeWithoutFlagSet();
            boolean with = probeWithFlagSet();
            if (!with) {
                throw new ProbeException("Target does not support key usage at all");
            }
            return new DigitalSignatureKeyUsageRequiredProbeResult(!without);
        } catch (VerifierException e) {
            throw new ProbeException("Unable to invoke verifier", e);
        } catch (CertificateGeneratorException e) {
            throw new ProbeException("Unable to generate certificate chain", e);
        }
    }

    private X509CertificateChainConfig prepareConfig(boolean digitalSignatureSet) {
        X509CertificateChainConfig config = X509CertificateConfigUtil.createBasicConfig(2);
        config.getEntityCertificateConfig().setIncludeExtensions(true);
        KeyUsageConfig extensionConfig = new KeyUsageConfig();
        extensionConfig.setPresent(true);
        extensionConfig.setCritical(true);
        config.getEntityCertificateConfig().addExtensions(extensionConfig);
        return config;
    }

    private VerifierResult invokeVerifier(X509CertificateChainConfig config)
        throws VerifierException, CertificateGeneratorException {
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(config);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateChain = certificateChainGenerator.retrieveCertificateChain();
        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter = VerifierAdapterFactory.getInstance(testConfig.getVerifierAdapterType(),
            testConfig.getVerifierAdapterConfig());
        return verifierAdapter.invokeVerifier(config.getEntityCertificateConfig(), certificateChain);
    }

    public boolean probeWithoutFlagSet() throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(false);
        return invokeVerifier(config).isValid();
    }

    public boolean probeWithFlagSet() throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(true);
        return invokeVerifier(config).isValid();
    }
}
