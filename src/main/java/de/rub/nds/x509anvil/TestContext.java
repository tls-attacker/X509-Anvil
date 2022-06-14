package de.rub.nds.x509anvil;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TestContext {
    private static final Logger LOGGER = LogManager.getLogger();

    private static TestContext instance;

    public synchronized static TestContext getInstance() {
        if (TestContext.instance == null) {
            TestContext.instance = new TestContext();
        }
        return TestContext.instance;
    }

    private TestContext() {

    }
}
