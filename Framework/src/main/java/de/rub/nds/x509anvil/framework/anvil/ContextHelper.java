package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureExtractor;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.featureextraction.UnsupportedFeatureException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;
import de.rub.nds.x509attacker.registry.Registry;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class ContextHelper {
    private static boolean contextInitialized = false;

    private static synchronized void setContext() throws UnsupportedFeatureException, ProbeException {
        Security.addProvider(new BouncyCastleProvider());
        Registry.getInstance();
        AnvilContext.getInstance().addParameterTypes(X509AnvilParameterType.values(), new X509AnvilParameterFactory());
        AnvilContext.getInstance().setModelBasedIpmFactory(new X509AnvilModelBasedIpmFactory());
        AnvilContext.getInstance().setApplicationSpecificContextDelegate(new X509AnvilContextDelegate(new TestConfig()));
        AnvilContext.getInstance().setTestStrength(2);

        FeatureReport report = FeatureExtractor.scanFeatures();
        ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).setFeatureReport(report);
    }

    public static synchronized void initializedContext() throws UnsupportedFeatureException, ProbeException {
        if (!contextInitialized) {
            setContext();
            contextInitialized = true;
        }
    }

    public static X509AnvilContextDelegate getContextDelegate() {
        return (X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate();
    }
}
