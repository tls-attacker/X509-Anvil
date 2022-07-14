/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.verifier;

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
