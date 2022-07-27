package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ExtensionProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SignatureAlgorithmProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.VersionProbeResult;

import java.util.ArrayList;
import java.util.List;

public class FeatureExtractor {
    public static FeatureReport scanFeatures() throws ProbeException, UnsupportedFeatureException {
        FeatureReport featureReport = new FeatureReport();

        // Probe supported versions
        List<Integer> supportedVersions = new ArrayList<>();
        for (int i = 0; i <= 2; i++) {
            Probe versionProbe = new VersionProbe(i);
            VersionProbeResult versionProbeResult = (VersionProbeResult) versionProbe.execute();
            if (versionProbeResult.isSupported()) {
                supportedVersions.add(i);
            }
            featureReport.addProbeResult(versionProbeResult);
        }
        featureReport.setSupportedVersions(supportedVersions);

        if (!featureReport.version3Supported()) {
            throw new UnsupportedFeatureException("Target verifier does not support certificates of version 3");
        }


        // Probe support for basic constraints extension
        Probe basicConstraintsProbe = new BasicConstraintsExtensionProbe();
        ExtensionProbeResult basicConstraintsProbeResult = (ExtensionProbeResult) basicConstraintsProbe.execute();
        if (!basicConstraintsProbeResult.isSupported()) {
            throw new UnsupportedFeatureException("Target verifier does not support basic constraints extension");
        }
        featureReport.addSupportedExtension(ExtensionType.BASIC_CONSTRAINTS);
        featureReport.addProbeResult(basicConstraintsProbeResult);


        // Probe support for signature algorithms
        List<SignatureAlgorithm> supportedAlgorithms = new ArrayList<>();
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            Probe signatureAlgorithmProbe = new SignatureAlgorithmProbe(algorithm);
            SignatureAlgorithmProbeResult signatureAlgorithmProbeResult = (SignatureAlgorithmProbeResult) signatureAlgorithmProbe.execute();
            if (signatureAlgorithmProbeResult.isSupported()) {
                supportedAlgorithms.add(algorithm);
            }
            featureReport.addProbeResult(signatureAlgorithmProbeResult);
        }
        featureReport.setSupportedAlgorithms(supportedAlgorithms);

        if (supportedAlgorithms.isEmpty()) {
            throw new UnsupportedFeatureException("Target verifier does not support any of the implemented signature algorithms");
        }


        // Probe support for other extensions
        // TODO

        return featureReport;
    }
}