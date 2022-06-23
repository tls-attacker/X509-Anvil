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
