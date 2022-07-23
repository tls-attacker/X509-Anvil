/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.x509anvil.framework.verifier.tlsclientauth.TlsClientAuthVerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterType;

public class TestConfig {
    // TODO: Use JCommander for config parameters

    private VerifierAdapterType verifierAdapterType = VerifierAdapterType.TLS_CLIENT_AUTH;
    private VerifierAdapterConfig verifierAdapterConfig =
        new TlsClientAuthVerifierAdapterConfig("192.168.178.66", 4433);
    private Boolean useStaticRootCertificate = true;
    private String staticRootCertificateFile = "resources/static-root/root-cert.pem";
    private String staticRootPrivateKeyFile = "resources/static-root/private-key.pem";

    private int defaultMinChainLength = 1;
    private int defaultMaxChainLength = 3;
    private int defaultIntermediateCertsModeled = 1;

    public VerifierAdapterType getVerifierAdapterType() {
        return verifierAdapterType;
    }

    public VerifierAdapterConfig getVerifierAdapterConfig() {
        return verifierAdapterConfig;
    }

    public int getDefaultMinChainLength() {
        return defaultMinChainLength;
    }

    public void setDefaultMinChainLength(int defaultMinChainLength) {
        this.defaultMinChainLength = defaultMinChainLength;
    }

    public int getDefaultMaxChainLength() {
        return defaultMaxChainLength;
    }

    public void setDefaultMaxChainLength(int defaultMaxChainLength) {
        this.defaultMaxChainLength = defaultMaxChainLength;
    }

    public int getDefaultIntermediateCertsModeled() {
        return defaultIntermediateCertsModeled;
    }

    public void setDefaultIntermediateCertsModeled(int defaultIntermediateCertsModeled) {
        this.defaultIntermediateCertsModeled = defaultIntermediateCertsModeled;
    }

    public Boolean getUseStaticRootCertificate() {
        return useStaticRootCertificate;
    }

    public void setUseStaticRootCertificate(Boolean useStaticRootCertificate) {
        this.useStaticRootCertificate = useStaticRootCertificate;
    }

    public String getStaticRootCertificateFile() {
        return staticRootCertificateFile;
    }

    public void setStaticRootCertificateFile(String staticRootCertificateFile) {
        this.staticRootCertificateFile = staticRootCertificateFile;
    }

    public String getStaticRootPrivateKeyFile() {
        return staticRootPrivateKeyFile;
    }

    public void setStaticRootPrivateKeyFile(String staticRootPrivateKeyFile) {
        this.staticRootPrivateKeyFile = staticRootPrivateKeyFile;
    }
}
