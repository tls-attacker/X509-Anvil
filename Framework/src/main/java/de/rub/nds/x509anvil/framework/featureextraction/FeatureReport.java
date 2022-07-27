package de.rub.nds.x509anvil.framework.featureextraction;

import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;

import java.util.ArrayList;
import java.util.List;


public class FeatureReport {
    private final List<ProbeResult> probeResults = new ArrayList<>();
    private List<Integer> supportedVersions = new ArrayList<>();
    private List<SignatureAlgorithm> supportedAlgorithms = new ArrayList<>();
    private List<ExtensionType> supportedExtensions = new ArrayList<>();

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

    @Override
    public String toString() {
        return "Supported versions: " + supportedVersions + "\n" +
                "Supported algorithms: " + supportedAlgorithms + "\n" +
                "Supported extensions: " + supportedExtensions;
    }
}
