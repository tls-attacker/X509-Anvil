/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.protocol.crypto.signature.RsaPkcs1SignatureComputations;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.crls.CrlUtils;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import org.apache.commons.lang3.RandomStringUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

public abstract class SimpleProbe implements Probe {


    @Override
    public ProbeResult execute() throws ProbeException {
        // dual config initialization here
        X509CertificateChainConfig config = prepareConfig();
        X509CertificateChainGenerator certificateChainGenerator =
                new X509CertificateChainGenerator(config);
        try {
            certificateChainGenerator.generateCertificateChain();
        } catch (CertificateGeneratorException e) {
            throw new ProbeException("Unable to generate certificate from config", e);
        }
        List<X509Certificate> certificateChain =
                certificateChainGenerator.retrieveCertificateChain();


        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter =
                VerifierAdapterFactory.getInstance(
                        testConfig.getVerifierAdapterType(), testConfig.getVerifierAdapterConfig());
        try {
            VerifierResult verifierResult =
                    verifierAdapter.invokeVerifier(
                            config.getEntityCertificateConfig(), certificateChain);
            return createResult(verifierResult);
        } catch (VerifierException e) {
            throw new ProbeException("Invoking the verifier for probe failed", e);
        }
    }

    protected abstract X509CertificateChainConfig prepareConfig();

    protected abstract ProbeResult createResult(VerifierResult verifierResult);
}


