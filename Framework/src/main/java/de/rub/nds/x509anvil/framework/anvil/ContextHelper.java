/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureExtractor;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.featureextraction.UnsupportedFeatureException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ContextHelper {

    private static FeatureReport featureReport = null;
    private static TestConfig testConfig = null;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static synchronized void initializeConfigs(String[] args) {
        if (testConfig == null) {
            testConfig = new TestConfig();
            if (args != null) {
                testConfig.parse(args);
            }
            AnvilContext.createInstance(
                    testConfig.getAnvilTestConfig(),
                    "",
                    new X509AnvilParameterIdentifierProvider());
        }
    }

    public static synchronized void initializefeatureReport()
            throws UnsupportedFeatureException, ProbeException {
        if (testConfig == null) {
            throw new UnsupportedOperationException(
                    "TestConfig is not initialized. Call initializeConfigs() first.");
        }
        if (featureReport == null) {
            featureReport = FeatureExtractor.scanFeatures();
        }
    }

    public static synchronized void initializeAll()
            throws UnsupportedFeatureException, ProbeException {
        initializeConfigs(null);
        initializefeatureReport();
    }

    public static FeatureReport getFeatureReport() {
        return featureReport;
    }

    public static TestConfig getTestConfig() {
        return testConfig;
    }
}
