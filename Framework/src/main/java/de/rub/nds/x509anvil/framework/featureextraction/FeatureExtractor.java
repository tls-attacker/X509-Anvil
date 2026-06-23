/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.probe.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.CNTypeProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SignatureAlgorithmProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.VersionProbeResult;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;

import java.util.ArrayList;
import java.util.List;

public class FeatureExtractor {
    public static FeatureReport scanFeatures() throws ProbeException, UnsupportedFeatureException {
        FeatureReport featureReport = new FeatureReport();

        // Probe supported versions
        scanForSupportedVersions(featureReport);

        // Probe support for signature algorithms (entity + intermediate)
        scanForSignatureHashAndKeyLengthAlgorithms(featureReport, true);
        scanForSignatureHashAndKeyLengthAlgorithms(featureReport, false);

        scanForSupportedCNTypes(featureReport);

        featureReport.addSupportedExtension(ExtensionType.BASIC_CONSTRAINTS);
        featureReport.addSupportedExtension(ExtensionType.KEY_USAGE);
        return featureReport;
    }

    private static void scanForSupportedCNTypes(FeatureReport featureReport) throws ProbeException {
        List<DirectoryStringChoiceType> supportedCNTypes = new ArrayList<>();
        for (DirectoryStringChoiceType directoryStringChoiceType : DirectoryStringChoiceType.values()) {
            CNTypeProbe cnTypeProbe = new CNTypeProbe(directoryStringChoiceType);
            CNTypeProbeResult cnTypeProbeResult = (CNTypeProbeResult) cnTypeProbe.execute();
            if (cnTypeProbeResult.isSupported()) {
                supportedCNTypes.add(cnTypeProbeResult.getDirectoryStringChoiceType());
            }
            featureReport.addProbeResult(cnTypeProbeResult);
        }
        featureReport.setSupportedCNTypes(supportedCNTypes);
    }

    private static void scanForSupportedVersions(FeatureReport featureReport)
            throws ProbeException, UnsupportedFeatureException {
        List<Integer> supportedVersions = new ArrayList<>();
        for (int i = 0; i <= 2; i++) {
            Probe versionProbe = new VersionProbe(i);
            VersionProbeResult versionProbeResult = (VersionProbeResult) versionProbe.execute();
            if (versionProbeResult.isSupported()) {
                supportedVersions.add(versionProbeResult.getVersion());
            }
            featureReport.addProbeResult(versionProbeResult);
        }
        featureReport.setSupportedVersions(supportedVersions);

        if (!featureReport.version3Supported()) {
            throw new UnsupportedFeatureException(
                    "Target verifier does not support certificates of version 3");
        }
    }

    private static void scanForSignatureHashAndKeyLengthAlgorithms(
            FeatureReport featureReport, boolean entity)
            throws UnsupportedFeatureException {
        List<SignatureHashAlgorithmKeyLengthPair> signatureHashAlgorithmKeyLengthPairs =
                new ArrayList<>();

        // produce all combinations of X509SignatureAlgorithm and the key pairs
        // evaluate combination

        for (SignatureHashAlgorithmKeyLengthPair algorithm :
                SignatureHashAlgorithmKeyLengthPair.generateAllPossibilities()) {
            Probe signatureAlgorithmProbe = new SignatureHashAndKeyLengthProbe(algorithm, entity);
            try {
                SignatureAlgorithmProbeResult signatureAlgorithmProbeResult =
                        (SignatureAlgorithmProbeResult) signatureAlgorithmProbe.execute();
                if (signatureAlgorithmProbeResult.isSupported()) {
                    signatureHashAlgorithmKeyLengthPairs.add(algorithm);
                }
                featureReport.addProbeResult(signatureAlgorithmProbeResult);
            } catch (Exception e) {
                featureReport.addProbeResult(new SignatureAlgorithmProbeResult(algorithm, false));
            }
        }

        if (entity) {
            featureReport.setSupportedSignatureHashAndKeyLengthPairsEntity(
                    signatureHashAlgorithmKeyLengthPairs);
        } else {
            featureReport.setSupportedSignatureHashAndKeyLengthPairsIntermediate(
                    signatureHashAlgorithmKeyLengthPairs);
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
