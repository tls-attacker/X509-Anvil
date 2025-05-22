package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.execution.TestRunner;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterIdentifierProvider;
import de.rub.nds.x509anvil.framework.featureextraction.UnsupportedFeatureException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;

import java.util.Random;

public class Main {
    public static void main(String[] args) throws UnsupportedFeatureException, ProbeException {

        // create the TLS-Anvil test context singleton
        ContextHelper.initializeContext();

        AnvilTestConfig anvilTestConfig = ContextHelper.getTestConfig().getAnvilTestConfig();
        anvilTestConfig.setStrength(1);
        anvilTestConfig.setDisableTcpDump(true);
        anvilTestConfig.setIgnoreCache(true);
        anvilTestConfig.setIdentifier("X509AnvilTest");
        anvilTestConfig.setOutputFolder("/tmp/X509-Anvil-Out-" + new Random().nextInt());
        anvilTestConfig.setTestPackage(ContextHelper.getTestConfig().getTestPackage());


        TestRunner testRunner = new TestRunner(anvilTestConfig, "placeholder", new X509AnvilParameterIdentifierProvider());
        testRunner.runTests();
    }
}
