/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.execution.TestRunner;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterIdentifierProvider;

import java.util.List;
import de.rub.nds.x509anvil.framework.verifier.adapter.TlsClientAuthVerifierAdapterDocker;
import de.rub.nds.x509anvil.framework.verifier.adapter.TlsServerAuthVerifierAdapterDocker;

public class Main {
    public static void main(String[] args) {

        // create the TLS-Anvil test context singleton
        ContextHelper.initializeConfigs(args);
        AnvilTestConfig anvilTestConfig = ContextHelper.getTestConfig().getAnvilTestConfig();
        anvilTestConfig.setDisableTcpDump(true);
        anvilTestConfig.setIgnoreCache(true);
        anvilTestConfig.setStrength(1);
        anvilTestConfig.setOutputFolder("results");
        anvilTestConfig.setIdentifier("x509tests");
        anvilTestConfig.setProfileFolder("./X509-Testsuite/profiles/");
        anvilTestConfig.setProfiles(List.of("everything"));

        TestRunner testRunner =
                new TestRunner(
                        anvilTestConfig, "placeholder", new X509AnvilParameterIdentifierProvider());
        testRunner.runTests();
        TlsClientAuthVerifierAdapterDocker.stopContainers();
        TlsServerAuthVerifierAdapterDocker.stopContainers();
    }

    static {
        Runtime.getRuntime()
                .addShutdownHook(
                        new Thread(
                                () -> {
                                    TlsClientAuthVerifierAdapterDocker.stopContainers();
                                    TlsServerAuthVerifierAdapterDocker.stopContainers();
                                }));
    }
}
