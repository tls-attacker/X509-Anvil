/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureExtractor;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.featureextraction.UnsupportedFeatureException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class ContextHelper {

    private static FeatureReport featureReport = null;
    private static boolean contextInitialized = false;

    private static TestConfig testConfig = null;

    private static synchronized void setContext() throws UnsupportedFeatureException, ProbeException {
        Security.addProvider(new BouncyCastleProvider());
        testConfig = new TestConfig();
        AnvilTestConfig anvilTestConfig = new AnvilTestConfig();
        anvilTestConfig.setStrength(2);
        AnvilContext.createInstance(anvilTestConfig, "", new X509AnvilParameterIdentifierProvider());

        featureReport = FeatureExtractor.scanFeatures();
    }

    public static synchronized void initializeContext() throws UnsupportedFeatureException, ProbeException {
        if (!contextInitialized) {
            setContext();
            contextInitialized = true;
        }
    }

    public static FeatureReport getFeatureReport() {
        return featureReport;
    }

    public static TestConfig getTestConfig() {
        return testConfig;
    }
}
