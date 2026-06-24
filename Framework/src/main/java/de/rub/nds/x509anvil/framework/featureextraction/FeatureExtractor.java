/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.x509anvil.framework.anvil.parameter.value.NotBeforeValue;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.probe.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.*;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;

import java.util.ArrayList;
import java.util.List;

public class FeatureExtractor {

    private static final List<Integer> toBeTestedSpecialPathLens = List.of(1000);

    public static FeatureReport scanFeatures() throws ProbeException, UnsupportedFeatureException {
        FeatureReport featureReport = new FeatureReport();

        // Probe supported versions
        scanForSupportedVersions(featureReport);

        // Probe support for signature algorithms (entity + intermediate)
        scanForSignatureHashAndKeyLengthAlgorithms(featureReport, true);
        scanForSignatureHashAndKeyLengthAlgorithms(featureReport, false);

        // Scan for other parameters
        scanForSupportedCNTypes(featureReport);
        scanForSupportedNotBefore(featureReport);
        scanForSupportedBasicConstraintsCa(featureReport);
        scanForSupportedPathLens(featureReport);
        scanForExtensionsAbsentEntity(featureReport);

        return featureReport;
    }

    private static void scanForExtensionsAbsentEntity(FeatureReport featureReport) throws ProbeException {
        ExtensionsPresentProbe extensionsPresentProbe = new ExtensionsPresentProbe();
        ExtensionsPresentResult extensionsPresentResult = (ExtensionsPresentResult) extensionsPresentProbe.execute();
        featureReport.addProbeResult(extensionsPresentResult);
        featureReport.setExtensionsAbsentEntitySupported(extensionsPresentResult.isSupported());
    }

    private static void scanForSupportedPathLens(FeatureReport featureReport) throws ProbeException {
        List<Integer> supportedPathLens = new ArrayList<>();
        for (int toBeTested : toBeTestedSpecialPathLens) {
            BasicConstraintsPathLenProbe basicConstraintsPathLenProbe = new BasicConstraintsPathLenProbe(toBeTested);
            BasicConstraintsPathLenResult basicConstraintsPathLenResult = (BasicConstraintsPathLenResult) basicConstraintsPathLenProbe.execute();
            if (basicConstraintsPathLenResult.isSupported()) {
                supportedPathLens.add(basicConstraintsPathLenResult.getPathLen());
            }
            featureReport.addProbeResult(basicConstraintsPathLenResult);
        }
        featureReport.setSupportedPathLens(supportedPathLens);
    }

    private static void scanForSupportedBasicConstraintsCa(FeatureReport featureReport) throws ProbeException {
        BasicConstraintsCaProbe basicConstraintsCaProbe = new BasicConstraintsCaProbe();
        BasicConstraintsCaResult basicConstraintsCaResult = (BasicConstraintsCaResult) basicConstraintsCaProbe.execute();
        featureReport.addProbeResult(basicConstraintsCaResult);
        featureReport.setBasicConstraintsCaEntitySupported(basicConstraintsCaResult.isSupported());
    }

    private static void scanForSupportedNotBefore(FeatureReport featureReport) throws ProbeException {
        List<NotBeforeValue> supportedNotBefores = new ArrayList<>();
        for (NotBeforeValue notBeforeValue : NotBeforeValue.values()) {
            NotBeforeProbe notBeforeProbe = new NotBeforeProbe(notBeforeValue);
            NotBeforeProbeResult notBeforeProbeResult = (NotBeforeProbeResult) notBeforeProbe.execute();
            if (notBeforeProbeResult.isSupported()) {
                supportedNotBefores.add(notBeforeProbeResult.getNotBeforeValue());
            }
            featureReport.addProbeResult(notBeforeProbeResult);
        }
        featureReport.setSupportedNotBefores(supportedNotBefores);
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
