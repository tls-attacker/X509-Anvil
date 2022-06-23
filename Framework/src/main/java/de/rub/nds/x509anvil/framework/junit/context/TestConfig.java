package de.rub.nds.x509anvil.framework.junit.context;

import de.rub.nds.x509anvil.framework.verifier.TlsClientAuthVerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterType;

public class TestConfig {
    // TODO: Use JCommander for config parameters

    private VerifierAdapterType verifierAdapterType = VerifierAdapterType.TLS_CLIENT_AUTH;
    private VerifierAdapterConfig verifierAdapterConfig = new TlsClientAuthVerifierAdapterConfig("192.168.56.101", 4433);


    public VerifierAdapterType getVerifierAdapterType() {
        return verifierAdapterType;
    }

    public VerifierAdapterConfig getVerifierAdapterConfig() {
        return verifierAdapterConfig;
    }
}
