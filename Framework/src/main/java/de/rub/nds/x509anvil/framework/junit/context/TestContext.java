/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.junit.context;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TestContext {
    private static final Logger LOGGER = LogManager.getLogger();

    private static TestContext instance;

    private final TestConfig testConfig = new TestConfig(); // TODO set properly

    public synchronized static TestContext getInstance() {
        if (TestContext.instance == null) {
            TestContext.instance = new TestContext();
        }
        return TestContext.instance;
    }

    private TestContext() {

    }

    public boolean testIsFinished(String uniqueId) {
        return false;
        // TODO
    }

    public TestConfig getTestConfig() {
        return testConfig;
    }
}
