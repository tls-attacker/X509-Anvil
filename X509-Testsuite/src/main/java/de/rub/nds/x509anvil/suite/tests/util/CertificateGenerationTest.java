/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateGenerationTest {
    protected static final Logger LOGGER = LogManager.getLogger();

    @AnvilTest(id = "cert-gen")
    public void exportSampleCertificates() {
        X509CertificateChainConfig chainConfig = new X509CertificateChainConfig();
        chainConfig.initializeChain(3, 1, true);

        X509CertificateChainGenerator chainGenerator =
                new X509CertificateChainGenerator(chainConfig);

        try {
            chainGenerator.generateCertificateChain();
        } catch (Exception e) {
            LOGGER.error("Could not generate certificates with: ", e);
        }

        X509Util.exportCertificates(chainGenerator.retrieveCertificateChain());
    }
}
