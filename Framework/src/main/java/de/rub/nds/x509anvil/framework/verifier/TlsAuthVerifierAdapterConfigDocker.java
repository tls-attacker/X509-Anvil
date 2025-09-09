package de.rub.nds.x509anvil.framework.verifier;

public class TlsAuthVerifierAdapterConfigDocker extends TlsAuthVerifierAdapterConfig {

    private static final short DOCKER_PORT = 27984;
    private String image;
    private String version;

    public TlsAuthVerifierAdapterConfigDocker(String image, String version) {
        super("localhost", DOCKER_PORT);
        this.image = image;
        this.version = version;
    }

    public String getImage() {
        return image;
    }

    public String getVersion() {
        return version;
    }
}
