/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.execution.TestRunner;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterIdentifierProvider;

import de.rub.nds.x509anvil.framework.verifier.adapter.TlsClientAuthVerifierAdapterDocker;
import de.rub.nds.x509anvil.framework.verifier.adapter.TlsServerAuthVerifierAdapterDocker;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;

public class Main {
    public static void main(String[] args) {
        ContextHelper.initializeConfigs(args);
        AnvilTestConfig anvilTestConfig = ContextHelper.getTestConfig().getAnvilTestConfig();

        generateCACert();

        TestRunner testRunner =
                new TestRunner(
                        anvilTestConfig, "placeholder", new X509AnvilParameterIdentifierProvider());
        testRunner.runTests();
    }

    static {
        Runtime.getRuntime()
                .addShutdownHook(
                        new Thread(
                                () -> {
                                    TlsClientAuthVerifierAdapterDocker.stopContainers();
                                    TlsServerAuthVerifierAdapterDocker.stopContainers();
                                }));
    }

    private static void generateCACert() {
        X509CertificateChainConfig chainConfig = new X509CertificateChainConfig();
        chainConfig.initializeChain(3, 1);

        X509CertificateChainGenerator chainGenerator =
                new X509CertificateChainGenerator(chainConfig);

        try {
            chainGenerator.generateCertificateChain();
        } catch (Exception e) {
            throw new RuntimeException("Could not generate certificates with: ", e);
        }

        X509Util.exportCertificates(chainGenerator.retrieveCertificateChain());
    }
}
