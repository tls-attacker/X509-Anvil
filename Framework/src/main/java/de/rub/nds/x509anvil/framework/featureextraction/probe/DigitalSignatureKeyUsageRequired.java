/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.DigitalSignatureKeyUsageRequiredProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.KeyUsageExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
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
        config.getEntityCertificateConfig().setExtensionsPresent(true);
        KeyUsageExtensionConfig extensionConfig =
            (KeyUsageExtensionConfig) config.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE);
        extensionConfig.setPresent(true);
        extensionConfig.setCritical(true);
        extensionConfig.setDataEncipherment(true); // At least one flag must be set
        extensionConfig.setDigitalSignature(digitalSignatureSet);
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
        return verifierAdapter.invokeVerifier(certificateChain, config);
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
