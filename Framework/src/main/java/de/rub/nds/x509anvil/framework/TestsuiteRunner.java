/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework;

import de.rub.nds.anvilcore.junit.extension.AnvilTestWatcher;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.core.LauncherConfig;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

public class TestsuiteRunner {
    private static final Logger logger = LogManager.getLogger();

    public static void runTests() {
        TestConfig testConfig = ContextHelper.getTestConfig();

        LauncherDiscoveryRequestBuilder discoveryRequestBuilder = LauncherDiscoveryRequestBuilder.request()
            .selectors(DiscoverySelectors.selectPackage(testConfig.getTestPackage()))
            .configurationParameter("junit.jupiter.execution.parallel.mode.default", "same_thread")
            .configurationParameter("junit.jupiter.execution.parallel.mode.classes.default", "concurrent")
            .configurationParameter("junit.jupiter.execution.parallel.config.strategy", "fixed")
            .configurationParameter("junit.jupiter.execution.parallel.config.fixed.parallelism",
                String.valueOf(testConfig.getNumParallelTests()));

        LauncherDiscoveryRequest launcherDiscoveryRequest = discoveryRequestBuilder.build();

        SummaryGeneratingListener summaryGeneratingListener = new SummaryGeneratingListener();
        TestExecutionListener executionListener = new AnvilTestWatcher();

        Launcher launcher = LauncherFactory.create(LauncherConfig.builder()
            .enableTestExecutionListenerAutoRegistration(false).addTestExecutionListeners(executionListener)
            .addTestExecutionListeners(summaryGeneratingListener).build());

        launcher.execute(launcherDiscoveryRequest);

        TestExecutionSummary summary = summaryGeneratingListener.getSummary();
        logger.info(summary.toString());

        System.exit(0);
    }
}
