/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.NONE,
        setterVisibility = JsonAutoDetect.Visibility.NONE,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.NONE)
public class TestConfig extends TLSDelegateConfig {

    protected static final Logger LOGGER = LogManager.getLogger();

    // TODO: Use JCommander for config parameters
    @JsonProperty private AnvilTestConfig anvilTestConfig = new AnvilTestConfig();

    private final VerifierAdapterConfig verifierAdapterConfig =
            new TlsAuthVerifierAdapterConfig("localhost", 4433);

    @JsonProperty("verifierAdapterType")
    @Parameter(
            names = "-verifierAdapterType",
            description = "Whether to test TLS servers or TLS clients.")
    private VerifierAdapterType verifierAdapterType = VerifierAdapterType.TLS_SERVER_AUTH;

    @JsonProperty("minChainLength")
    @Parameter(
            names = "-minChainLength",
            description =
                    "The default minimum chain length for the test cases. Ignored for test cases with annotated chain length.")
    private int defaultMinChainLength = 2;

    @JsonProperty("maxChainLength")
    @Parameter(
            names = "-maxChainLength",
            description =
                    "The default maximum chain length for the test cases. Ignored for test cases with annotated chain length.")
    private int defaultMaxChainLength = 4;

    @JsonProperty("intermediateCertsModeled")
    @Parameter(
            names = "-intermediateCertsModeled",
            description =
                    "The default number of intermediate certificated modeled. Ignored for test cases with annotated chain length.")
    private int defaultIntermediateCertsModeled = 2;

    public TestConfig() {
        super(new GeneralDelegate());
    }

    public void parse(String[] args) {

        JCommander argParser =
                JCommander.newBuilder().addObject(getAnvilTestConfig()).addObject(this).build();

        try {
            argParser.parse(args);
        } catch (ParameterException e) {
            LOGGER.error("Could not parse provided parameters", e);
            LOGGER.error("Provided parameters: {}", String.join(" ", args));
            argParser.usage();
            System.exit(2);
        }

        if (getGeneralDelegate().isHelp()) {
            argParser.usage();
            System.exit(0);
        }

        if (getAnvilTestConfig().getTestPackage() != null) {
            LOGGER.info(
                    "Limiting test to those of package {}", getAnvilTestConfig().getTestPackage());
        } else {
            // set test package if not specified via command args
            getAnvilTestConfig().setTestPackage("de.rub.nds.x509anvil.suite.tests");
        }
    }

    public AnvilTestConfig getAnvilTestConfig() {
        return anvilTestConfig;
    }

    public void setAnvilTestConfig(AnvilTestConfig anvilTestConfig) {
        this.anvilTestConfig = anvilTestConfig;
    }

    public VerifierAdapterType getVerifierAdapterType() {
        return verifierAdapterType;
    }

    public void setVerifierAdapterType(VerifierAdapterType verifierAdapterType) {
        this.verifierAdapterType = verifierAdapterType;
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
}
