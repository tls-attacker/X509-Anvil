/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.probe.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.DigitalSignatureKeyUsageRequiredProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ExtensionProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SignatureAlgorithmProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.VersionProbeResult;

import java.util.ArrayList;
import java.util.List;

public class FeatureExtractor {
    public static FeatureReport scanFeatures() throws ProbeException, UnsupportedFeatureException {
        FeatureReport featureReport = new FeatureReport();

        // Probe supported versions
        scanForSupportedVersions(featureReport);

        // Probe support for basic constraints extension
        scanForBasicConstraintsExtension(featureReport);

        // Probe support for key usage extension
        scanForKeyUsageExtension(featureReport);

        // Probe support for signature algorithms (entity + intermediate)
        scanForSignatureHashAndKeyLengthAlgorithms(featureReport, true);

        scanForSignatureHashAndKeyLengthAlgorithms(featureReport, false);

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

    private static void scanForBasicConstraintsExtension(FeatureReport featureReport) {
        // No need to check, all certs are generated with this anyway
        featureReport.addSupportedExtension(ExtensionType.BASIC_CONSTRAINTS);
    }

    private static void scanForSupportedVersions(FeatureReport featureReport)
        throws ProbeException, UnsupportedFeatureException {
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

    private static void scanForSignatureHashAndKeyLengthAlgorithms(FeatureReport featureReport, boolean entity)
        throws ProbeException, UnsupportedFeatureException {
        List<SignatureHashAlgorithmKeyLengthPair> signatureHashAlgorithmKeyLengthPairs = new ArrayList<>();

        // produce all combinations of X509SignatureAlgorithm and the key pairs
        // evaluate combination

        for (SignatureHashAlgorithmKeyLengthPair algorithm : SignatureHashAlgorithmKeyLengthPair
            .generateAllPossibilities()) {
            Probe signatureAlgorithmProbe = new SignatureHashAndKeyLengthProbe(algorithm, entity);
            SignatureAlgorithmProbeResult signatureAlgorithmProbeResult =
                (SignatureAlgorithmProbeResult) signatureAlgorithmProbe.execute();
            if (signatureAlgorithmProbeResult.isSupported()) {
                signatureHashAlgorithmKeyLengthPairs.add(algorithm);
            }
            featureReport.addProbeResult(signatureAlgorithmProbeResult);
        }

        if (entity) {
            featureReport.setSupportedSignatureHashAndKeyLengthPairsEntity(signatureHashAlgorithmKeyLengthPairs);
        } else {
            featureReport.setSupportedSignatureHashAndKeyLengthPairsIntermediate(signatureHashAlgorithmKeyLengthPairs);
        }

        if (signatureHashAlgorithmKeyLengthPairs.isEmpty()) {
            if (entity) {
                throw new UnsupportedFeatureException(
                    "Target verifier does not support any of the implemented signature algorithms for entity certificates");
            } else {
                throw new UnsupportedFeatureException(
                    "Target verifier does not support any of the implemented signature algorithms for intermediate certificates");
            }
        }
    }
}
