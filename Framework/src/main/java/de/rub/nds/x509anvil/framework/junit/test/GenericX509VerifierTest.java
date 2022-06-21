package de.rub.nds.x509anvil.framework.junit.test;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

public class GenericX509VerifierTest extends X509VerifierTest {
    @Override
    public X509CertificateChainConfig initConfig() {
        return new X509CertificateChainConfig();
    }
}
