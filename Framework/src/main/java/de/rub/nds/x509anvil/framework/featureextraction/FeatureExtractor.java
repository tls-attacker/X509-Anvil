/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithmLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.probe.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.*;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.util.ArrayList;
import java.util.List;

public class FeatureExtractor {
    public static FeatureReport scanFeatures() throws ProbeException, UnsupportedFeatureException {
        FeatureReport featureReport = new FeatureReport();

        // Probe supported versions
        scanForSupportedVersions(featureReport);

        // Probe support for basic constraints extension
        scanForBasicConstraintsExtension(featureReport);

        // Probe support for signature algorithms (entity)
        scanForSignatureAlgorithmsEntity(featureReport);

        // Probe support for key lengths (for entity certs)
        scanForSupportedKeyLengthsEntity(featureReport);

        // Probe support for signature algorithms (non-entity)
        scanForSignatureAlgorithmsNonEntity(featureReport);

        // Probe support for key lengths (for non-entity certs)
        scanForSupportedKeyLengthsNonEntity(featureReport);

        // Probe support for key usage extension
        scanForKeyUsageExtension(featureReport);

        return featureReport;
    }

    private static void scanForKeyUsageExtension(FeatureReport featureReport) throws ProbeException {
        Probe keyUsageProbe = new KeyUsageExtensionProbe();
        ExtensionProbeResult keyUsageProbeResult = (ExtensionProbeResult) keyUsageProbe.execute();
        if (keyUsageProbeResult.isSupported()) {
            featureReport.addSupportedExtension(ExtensionType.KEY_USAGE);
        }


        if (keyUsageProbeResult.isSupported()) {
            // Probe whether the digitalSignature key usage is required for entity certificates
            Probe digitalSignatureRequiredProbe = new DigitalSignatureKeyUsageRequired();
            DigitalSignatureKeyUsageRequiredProbeResult requiredProbeResult =
                (DigitalSignatureKeyUsageRequiredProbeResult) digitalSignatureRequiredProbe.execute();
            if (requiredProbeResult.isRequired()) {
                featureReport.setDigitalSignatureKeyUsageRequired(true);
            }
        }
    }

    private static void scanForSupportedKeyLengthsNonEntity(FeatureReport featureReport) throws ProbeException {
        List<SignatureAlgorithmLengthPair> supportedKeyLengths = new ArrayList<>();
        for (SignatureAlgorithm signatureAlgorithm : featureReport.getSupportedKeyTypes()) {
            for (int keyLength : SignatureAlgorithmLengthPair.getKeyLengths(signatureAlgorithm)) {
                X509SignatureAlgorithm x509SignatureAlgorithm = featureReport.getSupportedAlgorithms().stream()
                    .filter(a -> a.getSignatureAlgorithm() == signatureAlgorithm).findFirst().get();
                Probe keyLengthProbe = new KeyLengthProbe(x509SignatureAlgorithm, keyLength, false);
                KeyLengthProbeResult signatureAlgorithmProbeResult = (KeyLengthProbeResult) keyLengthProbe.execute();
                if (signatureAlgorithmProbeResult.isSupported()) {
                    supportedKeyLengths.add(SignatureAlgorithmLengthPair.get(signatureAlgorithm, keyLength));
                }
            }
        }
        featureReport.setSupportedKeyLengths(supportedKeyLengths);
    }

    private static void scanForSignatureAlgorithmsNonEntity(FeatureReport featureReport) throws ProbeException, UnsupportedFeatureException {
        List<X509SignatureAlgorithm> supportedAlgorithms = new ArrayList<>();
        for (X509SignatureAlgorithm algorithm : X509SignatureAlgorithm.values()) {
            Probe signatureAlgorithmProbe = new SignatureAlgorithmProbe(algorithm);
            SignatureAlgorithmProbeResult signatureAlgorithmProbeResult =
                (SignatureAlgorithmProbeResult) signatureAlgorithmProbe.execute();
            if (signatureAlgorithmProbeResult.isSupported()) {
                supportedAlgorithms.add(algorithm);
            }
            featureReport.addProbeResult(signatureAlgorithmProbeResult);
        }
        featureReport.setSupportedAlgorithms(supportedAlgorithms);

        if (supportedAlgorithms.isEmpty()) {
            throw new UnsupportedFeatureException(
                "Target verifier does not support any of the implemented signature algorithms");
        }
    }

    private static void scanForSupportedKeyLengthsEntity(FeatureReport featureReport) throws ProbeException {
        List<SignatureAlgorithmLengthPair> supportedEntityKeyLengths = new ArrayList<>();
        for (SignatureAlgorithm signatureAlgorithm : featureReport.getSupportedEntityKeyTypes()) {
            for (int keyLength : SignatureAlgorithmLengthPair.getKeyLengths(signatureAlgorithm)) {
                X509SignatureAlgorithm x509signatureAlgorithm = featureReport.getSupportedEntityAlgorithms().stream()
                    .filter(a -> a.getSignatureAlgorithm() == signatureAlgorithm).findFirst().get();
                Probe keyLengthProbe = new KeyLengthProbe(x509signatureAlgorithm, keyLength, true);
                KeyLengthProbeResult signatureAlgorithmProbeResult = (KeyLengthProbeResult) keyLengthProbe.execute();
                if (signatureAlgorithmProbeResult.isSupported()) {
                    supportedEntityKeyLengths.add(SignatureAlgorithmLengthPair.get(signatureAlgorithm, keyLength));
                }
            }
        }
        featureReport.setSupportedEntityKeyLengths(supportedEntityKeyLengths);
    }

    private static void scanForSignatureAlgorithmsEntity(FeatureReport featureReport) throws ProbeException, UnsupportedFeatureException {
        List<X509SignatureAlgorithm> supportedEntityAlgorithms = new ArrayList<>();
        for (X509SignatureAlgorithm algorithm : X509SignatureAlgorithm.values()) {
            Probe entitySignatureAlgorithmProbe = new EntitySignatureAlgorithmProbe(algorithm);
            SignatureAlgorithmProbeResult signatureAlgorithmProbeResult =
                (SignatureAlgorithmProbeResult) entitySignatureAlgorithmProbe.execute();
            if (signatureAlgorithmProbeResult.isSupported()) {
                supportedEntityAlgorithms.add(algorithm);
            }
            featureReport.addProbeResult(signatureAlgorithmProbeResult);
        }
        featureReport.setSupportedEntityAlgorithms(supportedEntityAlgorithms);

        if (supportedEntityAlgorithms.isEmpty()) {
            throw new UnsupportedFeatureException(
                "Target verifier does not support any of the implemented signature algorithms for entity certificates");
        }
    }

    private static void scanForBasicConstraintsExtension(FeatureReport featureReport) throws ProbeException, UnsupportedFeatureException {
        Probe basicConstraintsProbe = new BasicConstraintsExtensionProbe();
        ExtensionProbeResult basicConstraintsProbeResult = (ExtensionProbeResult) basicConstraintsProbe.execute();
        if (!basicConstraintsProbeResult.isSupported()) {
            throw new UnsupportedFeatureException("Target verifier does not support basic constraints extension");
        }
        featureReport.addSupportedExtension(ExtensionType.BASIC_CONSTRAINTS);
        featureReport.addProbeResult(basicConstraintsProbeResult);
        featureReport.addProbeResult(basicConstraintsProbeResult);
    }

    private static void scanForSupportedVersions(FeatureReport featureReport) throws ProbeException, UnsupportedFeatureException {
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
    }
}
