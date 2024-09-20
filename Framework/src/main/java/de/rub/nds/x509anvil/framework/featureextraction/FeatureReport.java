/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.anvil.parameter.SignatureHashAndLengthParameter;
import de.rub.nds.x509anvil.framework.constants.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.util.*;
import java.util.stream.Collectors;

public class FeatureReport {
    private final List<ProbeResult> probeResults = new ArrayList<>();
    private List<Integer> supportedVersions = new ArrayList<>();
    private List<ExtensionType> supportedExtensions = new ArrayList<>();

    private List<SignatureHashAlgorithmKeyLengthPair> supportedSignatureHashAndKeyLengthPairs = new ArrayList<>();
    private boolean digitalSignatureKeyUsageRequired;

    public List<ProbeResult> getProbeResults() {
        return probeResults;
    }

    public void addProbeResult(ProbeResult probeResult) {
        probeResults.add(probeResult);
    }

    public List<Integer> getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(List<Integer> supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    public boolean version1Supported() {
        return supportedVersions.contains(0);
    }

    public boolean version2Supported() {
        return supportedVersions.contains(1);
    }

    public boolean version3Supported() {
        return supportedVersions.contains(2);
    }
    public List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public void addSupportedExtension(ExtensionType extensionType) {
        supportedExtensions.add(extensionType);
    }

    public boolean extensionSupported(ExtensionType extensionType) {
        return supportedExtensions.contains(extensionType);
    }

    public boolean isDigitalSignatureKeyUsageRequired() {
        return digitalSignatureKeyUsageRequired;
    }

    public void setDigitalSignatureKeyUsageRequired(boolean digitalSignatureKeyUsageRequired) {
        this.digitalSignatureKeyUsageRequired = digitalSignatureKeyUsageRequired;
    }

    public List<SignatureHashAlgorithmKeyLengthPair> getSupportedSignatureHashAndKeyLengthPairs() {
        return supportedSignatureHashAndKeyLengthPairs;
    }

    public void setSupportedSignatureHashAndKeyLengthPairs(List<SignatureHashAlgorithmKeyLengthPair> supportedSignatureHashAndKeyLengthPairs) {
        this.supportedSignatureHashAndKeyLengthPairs = supportedSignatureHashAndKeyLengthPairs;
    }

    @Override
    public String toString() {
        return "Supported versions: " + supportedVersions + "\n" + "Supported Signature and HashAlgorithm and Key Length triples: " + supportedSignatureHashAndKeyLengthPairs + "\n"
            + "Supported extensions: " + supportedExtensions;
    }

}
