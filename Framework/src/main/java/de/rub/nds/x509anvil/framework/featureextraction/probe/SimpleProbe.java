/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.NopX509CertificateModifier;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.util.List;

public abstract class SimpleProbe implements Probe {

    @Override
    public ProbeResult execute() throws ProbeException {
        X509CertificateChainConfig config = prepareConfig();
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(config);
        certificateChainGenerator.addModifier(createModifier());
        try {
            certificateChainGenerator.generateCertificateChain();
        } catch (CertificateGeneratorException e) {
            throw new ProbeException("Unable to generate certificate from config", e);
        }
        List<X509Certificate> certificateChain = certificateChainGenerator.retrieveCertificateChain();

        TestConfig testConfig =
            ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate())
                .getTestConfig();
        VerifierAdapter verifierAdapter = VerifierAdapterFactory.getInstance(testConfig.getVerifierAdapterType(),
            testConfig.getVerifierAdapterConfig());
        try {
            VerifierResult verifierResult = verifierAdapter.invokeVerifier(certificateChain, config);
            return createResult(verifierResult);
        } catch (VerifierException e) {
            throw new ProbeException("Invoking the verifier for probe failed", e);
        }
    }

    protected abstract X509CertificateChainConfig prepareConfig();

    protected abstract ProbeResult createResult(VerifierResult verifierResult);

    protected X509CertificateModifier createModifier() {
        return new NopX509CertificateModifier();
    }

}