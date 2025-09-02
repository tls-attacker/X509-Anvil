package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.execution.TestRunner;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterIdentifierProvider;

public class Main {
    public static void main(String[] args) {

        // create the TLS-Anvil test context singleton
        ContextHelper.initializeConfigs(args);
        AnvilTestConfig anvilTestConfig = ContextHelper.getTestConfig().getAnvilTestConfig();
        anvilTestConfig.setDisableTcpDump(true);
        anvilTestConfig.setIgnoreCache(true);
        anvilTestConfig.setStrength(1);
        anvilTestConfig.setOutputFolder("results");

        TestRunner testRunner = new TestRunner(anvilTestConfig, "placeholder", new X509AnvilParameterIdentifierProvider());
        testRunner.runTests();
    }
}
