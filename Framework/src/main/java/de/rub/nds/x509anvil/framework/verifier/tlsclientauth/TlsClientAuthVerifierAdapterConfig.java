/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.verifier.tlsclientauth;

import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterConfig;

public class TlsClientAuthVerifierAdapterConfig implements VerifierAdapterConfig {
    private String hostname;
    private int port;

    public TlsClientAuthVerifierAdapterConfig(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
    }

    public TlsClientAuthVerifierAdapterConfig() {
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }
}
