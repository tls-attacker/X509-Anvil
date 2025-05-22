/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterType;
import de.rub.nds.x509anvil.framework.verifier.tlsclientauth.TlsClientAuthVerifierAdapterConfig;

public class TestConfig {
    // TODO: Use JCommander for config parameters
    private AnvilTestConfig anvilTestConfig = new AnvilTestConfig();

    private final VerifierAdapterType verifierAdapterType = VerifierAdapterType.TLS_CLIENT_AUTH;
    private final VerifierAdapterConfig verifierAdapterConfig =
        new TlsClientAuthVerifierAdapterConfig("localhost", 4433);
    private Boolean useStaticRootCertificate = true;

    private int defaultMinChainLength = 4;
    private int defaultMaxChainLength = 4;
    private int defaultIntermediateCertsModeled = 2;

    private String testPackage = "de.rub.nds.x509anvil.suite.tests";

    public AnvilTestConfig getAnvilTestConfig() {
        return anvilTestConfig;
    }

    public void setAnvilTestConfig(AnvilTestConfig anvilTestConfig) {
        this.anvilTestConfig = anvilTestConfig;
    }

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

    public String getTestPackage() {
        return testPackage;
    }

    public void setTestPackage(String testPackage) {
        this.testPackage = testPackage;
    }
}
