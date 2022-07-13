package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.ApplicationSpecificContextDelegate;
import de.rub.nds.x509anvil.framework.junit.context.TestConfig;

public class X509AnvilContextDelegate implements ApplicationSpecificContextDelegate {
    private final TestConfig testConfig;

    public X509AnvilContextDelegate(TestConfig testConfig) {
        this.testConfig = testConfig;
    }

    public TestConfig getTestConfig() {
        return testConfig;
    }
}
