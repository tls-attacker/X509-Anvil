/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.junit.context;

import de.rub.nds.x509anvil.framework.verifier.TlsClientAuthVerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterType;

public class TestConfig {
    // TODO: Use JCommander for config parameters

    private VerifierAdapterType verifierAdapterType = VerifierAdapterType.TLS_CLIENT_AUTH;
    private VerifierAdapterConfig verifierAdapterConfig =
        new TlsClientAuthVerifierAdapterConfig("192.168.178.66", 4433);
    private Boolean useStaticRootCertificate = true;
    private String staticRootCertificateFile = "";
    private String staticRootPrivateKeyFile = "";

    public VerifierAdapterType getVerifierAdapterType() {
        return verifierAdapterType;
    }

    public VerifierAdapterConfig getVerifierAdapterConfig() {
        return verifierAdapterConfig;
    }
}
