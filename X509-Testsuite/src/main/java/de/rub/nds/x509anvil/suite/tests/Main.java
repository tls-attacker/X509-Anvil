package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.x509anvil.framework.TestsuiteRunner;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.featureextraction.UnsupportedFeatureException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;

public class Main {
    public static void main(String[] args) throws ProbeException, UnsupportedFeatureException {
        ContextHelper.initializedContext();
        // TODO: Parse config from file

        TestsuiteRunner.runTests();
    }
}
