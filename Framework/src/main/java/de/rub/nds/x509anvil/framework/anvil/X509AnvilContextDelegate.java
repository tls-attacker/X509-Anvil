/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.ApplicationSpecificContextDelegate;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;

public class X509AnvilContextDelegate implements ApplicationSpecificContextDelegate {
    private final TestConfig testConfig;
    private FeatureReport featureReport = null;

    public X509AnvilContextDelegate(TestConfig testConfig) {
        this.testConfig = testConfig;
    }

    public TestConfig getTestConfig() {
        return testConfig;
    }

    public FeatureReport getFeatureReport() {
        return featureReport;
    }

    public void setFeatureReport(FeatureReport featureReport) {
        this.featureReport = featureReport;
    }
}
