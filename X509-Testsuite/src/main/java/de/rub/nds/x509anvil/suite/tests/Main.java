package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.x509anvil.framework.TestsuiteRunner;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.featureextraction.UnsupportedFeatureException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;

public class Main {
    public static void main(String[] args) throws ProbeException, UnsupportedFeatureException {
        ContextHelper.initializeContext();
        // TODO: Parse config from file

        //TODO: Generate sample configs and save
        TestsuiteRunner.runTests();
    }
}
