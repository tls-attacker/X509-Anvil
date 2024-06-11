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
import de.rub.nds.x509anvil.framework.constants.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.util.*;
import java.util.stream.Collectors;

public class FeatureReport {
    private final List<ProbeResult> probeResults = new ArrayList<>();
    private List<Integer> supportedVersions = new ArrayList<>();
    private List<X509SignatureAlgorithm> supportedAlgorithms = new ArrayList<>();
    private List<X509SignatureAlgorithm> supportedEntityAlgorithms = new ArrayList<>();
    private List<SignatureAlgorithmLengthPair> supportedKeyLengths = new ArrayList<>();
    private List<SignatureAlgorithmLengthPair> supportedEntityKeyLengths = new ArrayList<>();
    private List<ExtensionType> supportedExtensions = new ArrayList<>();
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

    public List<X509SignatureAlgorithm> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    public void setSupportedAlgorithms(List<X509SignatureAlgorithm> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

    public boolean algorithmSupported(X509SignatureAlgorithm algorithm) {
        return supportedAlgorithms.contains(algorithm);
    }

    public boolean entityAlgorithmSupported(X509SignatureAlgorithm algorithm) {
        return supportedEntityAlgorithms.contains(algorithm);
    }

    public boolean keyTypeSupported(SignatureAlgorithm keyType) {
        return supportedAlgorithms.stream().anyMatch(a -> a.getSignatureAlgorithm().equals(keyType));
    }

    public boolean entityKeyTypeSupported(SignatureAlgorithm keyType) {
        return supportedEntityAlgorithms.stream().anyMatch(a -> a.getSignatureAlgorithm().equals(keyType));
    }

    public List<SignatureAlgorithm> getSupportedKeyTypes() {
        return Arrays.stream(SignatureAlgorithm.values()).filter(this::keyTypeSupported).collect(Collectors.toList());
    }

    public List<SignatureAlgorithm> getSupportedEntityKeyTypes() {
        return Arrays.stream(SignatureAlgorithm.values()).filter(this::entityKeyTypeSupported)
            .collect(Collectors.toList());
    }

    public boolean hashAlgorithmSupported(HashAlgorithm hashAlgorithm) {
        return supportedAlgorithms.stream().anyMatch(a -> a.getHashAlgorithm().equals(hashAlgorithm));
    }

    public boolean entityHashAlgorithmSupported(HashAlgorithm hashAlgorithm) {
        return supportedEntityAlgorithms.stream().anyMatch(a -> a.getHashAlgorithm().equals(hashAlgorithm));
    }

    public List<HashAlgorithm> getSupportedHashAlgorithms() {
        return Arrays.stream(HashAlgorithm.values()).filter(this::hashAlgorithmSupported).collect(Collectors.toList());
    }

    public List<HashAlgorithm> getSupportedEntityHashAlgorithms() {
        return Arrays.stream(HashAlgorithm.values()).filter(this::entityHashAlgorithmSupported)
            .collect(Collectors.toList());
    }

    public List<SignatureAlgorithmLengthPair> getSupportedKeyLengths() {
        return supportedKeyLengths;
    }

    public void setSupportedKeyLengths(List<SignatureAlgorithmLengthPair> supportedKeyLengths) {
        this.supportedKeyLengths = supportedKeyLengths;
    }

    public List<SignatureAlgorithmLengthPair> getSupportedEntityKeyLengths() {
        return supportedEntityKeyLengths;
    }

    public void setSupportedEntityKeyLengths(List<SignatureAlgorithmLengthPair> supportedEntityKeyLengths) {
        this.supportedEntityKeyLengths = supportedEntityKeyLengths;
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

    @Override
    public String toString() {
        return "Supported versions: " + supportedVersions + "\n" + "Supported algorithms: " + supportedAlgorithms + "\n"
            + "Supported extensions: " + supportedExtensions;
    }

    public List<X509SignatureAlgorithm> getSupportedEntityAlgorithms() {
        return supportedEntityAlgorithms;
    }

    public void setSupportedEntityAlgorithms(List<X509SignatureAlgorithm> supportedEntityAlgorithms) {
        this.supportedEntityAlgorithms = supportedEntityAlgorithms;
    }
}
