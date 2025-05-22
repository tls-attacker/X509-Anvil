package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

public class CertificateGenerationTest {
    protected static final Logger LOGGER = LogManager.getLogger();

    @Test
    public void exportSampleCertificates() {
        X509CertificateChainConfig chainConfig = new X509CertificateChainConfig();
        chainConfig.initializeChain(3,1);

        X509CertificateChainGenerator chainGenerator = new X509CertificateChainGenerator(chainConfig);

        try {
            chainGenerator.generateCertificateChain();
        } catch (Exception e) {
            LOGGER.error("Could not generate certificates with: ", e);
        }

        X509Util.exportCertificates(chainGenerator.retrieveCertificateChain(), "resources/out");
    }
}
