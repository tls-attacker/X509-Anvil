package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.x509anvil.framework.constants.*;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;

import java.util.*;
import java.util.stream.Collectors;


public class FeatureReport {
    private final List<ProbeResult> probeResults = new ArrayList<>();
    private List<Integer> supportedVersions = new ArrayList<>();
    private List<SignatureAlgorithm> supportedAlgorithms = new ArrayList<>();
    private List<KeyTypeLengthPair> supportedKeyLengths = new ArrayList<>();
    private List<KeyTypeLengthPair> supportedEntityKeyLengths = new ArrayList<>();
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

    public List<SignatureAlgorithm> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    public void setSupportedAlgorithms(List<SignatureAlgorithm> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

    public boolean algorithmSupported(SignatureAlgorithm algorithm) {
        return supportedAlgorithms.contains(algorithm);
    }

    public boolean keyTypeSupported(KeyType keyType) {
        return supportedAlgorithms.stream().anyMatch(a -> a.getKeyType().equals(keyType));
    }

    public List<KeyType> getSupportedKeyTypes() {
        return Arrays.stream(KeyType.values())
                .filter(this::keyTypeSupported)
                .collect(Collectors.toList());
    }

    public boolean hashAlgorithmSupported(HashAlgorithm hashAlgorithm) {
        return supportedAlgorithms.stream().anyMatch(a -> a.getHashAlgorithm().equals(hashAlgorithm));
    }

    public List<HashAlgorithm> getSupportedHashAlgorithms() {
        return Arrays.stream(HashAlgorithm.values())
                .filter(this::hashAlgorithmSupported)
                .collect(Collectors.toList());
    }

    public List<KeyTypeLengthPair> getSupportedKeyLengths() {
        return supportedKeyLengths;
    }

    public void setSupportedKeyLengths(List<KeyTypeLengthPair> supportedKeyLengths) {
        this.supportedKeyLengths = supportedKeyLengths;
    }

    public List<KeyTypeLengthPair> getSupportedEntityKeyLengths() {
        return supportedEntityKeyLengths;
    }

    public void setSupportedEntityKeyLengths(List<KeyTypeLengthPair> supportedEntityKeyLengths) {
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
        return "Supported versions: " + supportedVersions + "\n" +
                "Supported algorithms: " + supportedAlgorithms + "\n" +
                "Supported extensions: " + supportedExtensions;
    }
}
