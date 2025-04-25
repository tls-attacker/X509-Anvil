/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
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

public abstract class SimpleProbe implements Probe {

    @Override
    public ProbeResult execute() throws ProbeException {
        // dual config initialization here
        X509CertificateChainConfig config = prepareConfig();
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(config);
        try {
            certificateChainGenerator.generateCertificateChain();
        } catch (CertificateGeneratorException e) {
            throw new ProbeException("Unable to generate certificate from config", e);
        }
        List<X509Certificate> certificateChain = certificateChainGenerator.retrieveCertificateChain();

        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter = VerifierAdapterFactory.getInstance(testConfig.getVerifierAdapterType(),
            testConfig.getVerifierAdapterConfig());
        try {
            VerifierResult verifierResult =
                verifierAdapter.invokeVerifier(config.getEntityCertificateConfig(), certificateChain);
            return createResult(verifierResult);
        } catch (VerifierException e) {
            throw new ProbeException("Invoking the verifier for probe failed", e);
        }
    }

    protected abstract X509CertificateChainConfig prepareConfig();

    protected abstract ProbeResult createResult(VerifierResult verifierResult);

}