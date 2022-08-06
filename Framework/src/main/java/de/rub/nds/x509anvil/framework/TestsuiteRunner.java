package de.rub.nds.x509anvil.framework;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.listeners.LoggingListener;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;

import java.util.logging.Level;

public class TestsuiteRunner {
    public void runTests() {
        TestConfig testConfig = ContextHelper.getContextDelegate().getTestConfig();

        LauncherDiscoveryRequestBuilder discoveryRequestBuilder = LauncherDiscoveryRequestBuilder.request()
                .selectors(DiscoverySelectors.selectPackage(testConfig.getTestPackage()))
                .configurationParameter("junit.jupiter.execution.parallel.mode.default", "same_thread")
                .configurationParameter("junit.jupiter.execution.parallel.mode.classes.default", "concurrent")
                .configurationParameter("junit.jupiter.execution.parallel.config.strategy", "fixed")
                .configurationParameter("junit.jupiter.execution.parallel.config.fixed.parallelism", String.valueOf(testConfig.getNumParallelTests()));

        LauncherDiscoveryRequest launcherDiscoveryRequest = discoveryRequestBuilder.build();

        SummaryGeneratingListener summaryGeneratingListener = new SummaryGeneratingListener();
        LoggingListener loggingListener = LoggingListener.forJavaUtilLogging(Level.INFO);
    }
}
