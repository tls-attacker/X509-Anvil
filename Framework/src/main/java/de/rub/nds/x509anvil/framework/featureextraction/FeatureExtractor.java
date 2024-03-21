/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.constants.KeyTypeLengthPair;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.*;

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

        // Probe support for signature algorithms (entity)
        List<SignatureAlgorithm> supportedEntityAlgorithms = new ArrayList<>();
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
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

        // Probe support for key lengths (for entity certs)
        List<KeyTypeLengthPair> supportedEntityKeyLengths = new ArrayList<>();
        for (KeyType keyType : featureReport.getSupportedEntityKeyTypes()) {
            for (int keyLength : KeyTypeLengthPair.getKeyLengths(keyType)) {
                SignatureAlgorithm signatureAlgorithm = featureReport.getSupportedEntityAlgorithms().stream()
                    .filter(a -> a.getKeyType() == keyType).findFirst().get();
                Probe keyLengthProbe = new KeyLengthProbe(signatureAlgorithm, keyLength, true);
                KeyLengthProbeResult signatureAlgorithmProbeResult = (KeyLengthProbeResult) keyLengthProbe.execute();
                if (signatureAlgorithmProbeResult.isSupported()) {
                    supportedEntityKeyLengths.add(KeyTypeLengthPair.get(keyType, keyLength));
                }
            }
        }
        featureReport.setSupportedEntityKeyLengths(supportedEntityKeyLengths);

        // Probe support for signature algorithms (non-entity)
        List<SignatureAlgorithm> supportedAlgorithms = new ArrayList<>();
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
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

        // Probe support for key lengths (for non-entity certs)
        List<KeyTypeLengthPair> supportedKeyLengths = new ArrayList<>();
        for (KeyType keyType : featureReport.getSupportedKeyTypes()) {
            for (int keyLength : KeyTypeLengthPair.getKeyLengths(keyType)) {
                SignatureAlgorithm signatureAlgorithm = featureReport.getSupportedAlgorithms().stream()
                    .filter(a -> a.getKeyType() == keyType).findFirst().get();
                Probe keyLengthProbe = new KeyLengthProbe(signatureAlgorithm, keyLength, false);
                KeyLengthProbeResult signatureAlgorithmProbeResult = (KeyLengthProbeResult) keyLengthProbe.execute();
                if (signatureAlgorithmProbeResult.isSupported()) {
                    supportedKeyLengths.add(KeyTypeLengthPair.get(keyType, keyLength));
                }
            }
        }
        featureReport.setSupportedKeyLengths(supportedKeyLengths);

        // Probe support for key usage extension
        Probe keyUsageProbe = new KeyUsageExtensionProbe();
        ExtensionProbeResult keyUsageProbeResult = (ExtensionProbeResult) keyUsageProbe.execute();
        if (keyUsageProbeResult.isSupported()) {
            featureReport.addSupportedExtension(ExtensionType.KEY_USAGE);
        }
        featureReport.addProbeResult(basicConstraintsProbeResult);

        if (keyUsageProbeResult.isSupported()) {
            // Probe whether the digitalSignature key usage is required for entity certificates
            Probe digitalSignatureRequiredProbe = new DigitalSignatureKeyUsageRequired();
            DigitalSignatureKeyUsageRequiredProbeResult requiredProbeResult =
                (DigitalSignatureKeyUsageRequiredProbeResult) digitalSignatureRequiredProbe.execute();
            if (requiredProbeResult.isRequired()) {
                featureReport.setDigitalSignatureKeyUsageRequired(true);
            }
        }

        return featureReport;
    }
}
