/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
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
