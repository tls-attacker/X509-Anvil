/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509attacker.x509.X509Certificate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.List;

public class X509VerifierRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private X509CertificateChainConfig preparedConfig;
    private ParameterCombination parameterCombination;
    private final ExtensionContext extensionContext;

    public X509VerifierRunner(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    public X509VerifierRunner(ExtensionContext extensionContext, X509CertificateChainConfig config) {
        this(extensionContext);
        this.preparedConfig = config;
    }

    public X509CertificateChainConfig getPreparedConfig() {
        return preparedConfig;
    }

    public void setPreparedConfig(X509CertificateChainConfig preparedConfig) {
        this.preparedConfig = preparedConfig;
    }

    public ParameterCombination getParameterCombination() {
        return parameterCombination;
    }

    public void setParameterCombination(ParameterCombination parameterCombination) {
        this.parameterCombination = parameterCombination;
    }

    public VerifierResult execute(X509CertificateChainConfig config)
        throws CertificateGeneratorException, VerifierException {
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(config);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateList = certificateChainGenerator.retrieveCertificateChain();
        X509Util.exportCertificates(certificateList, "resources");

        TestConfig testConfig =
            ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate())
                .getTestConfig();
        VerifierAdapter verifierAdapter = VerifierAdapterFactory.getInstance(testConfig.getVerifierAdapterType(),
            testConfig.getVerifierAdapterConfig());
        return verifierAdapter.invokeVerifier(certificateList, config);
    }
}
