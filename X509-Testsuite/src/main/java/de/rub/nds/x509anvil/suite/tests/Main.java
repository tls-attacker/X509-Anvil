package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.anvil.*;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.Probe;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.SignatureAlgorithmProbe;
import de.rub.nds.x509anvil.framework.featureextraction.probe.VersionProbe;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509attacker.registry.Registry;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {
    public static void main(String[] args) throws ProbeException {
        Security.addProvider(new BouncyCastleProvider());
        Registry.getInstance();
        AnvilContext.getInstance().addParameterTypes(X509AnvilParameterType.values(), new X509AnvilParameterFactory());
        AnvilContext.getInstance().setModelBasedIpmFactory(new X509AnvilModelBasedIpmFactory());
        AnvilContext.getInstance().setApplicationSpecificContextDelegate(new X509AnvilContextDelegate(new TestConfig()));
        AnvilContext.getInstance().setTestStrength(2);

        Probe versionProbe = new VersionProbe(0);
        ProbeResult result = versionProbe.execute();
        System.out.println(result);

        Probe signatureAlgorithmProbe = new SignatureAlgorithmProbe(SignatureAlgorithm.DSA_SHA512);
        ProbeResult result1 = signatureAlgorithmProbe.execute();
        System.out.println(result);
    }
}
