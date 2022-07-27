package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ExtensionProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.NopX509CertificateModifier;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.util.List;

public abstract class ExtensionProbe implements Probe {
    private final ExtensionType extensionType;

    protected ExtensionProbe(ExtensionType extensionType) {
        this.extensionType = extensionType;
    }

    @Override
    public ProbeResult execute() throws ProbeException {
        try {
            X509CertificateChainConfig baseConfig = prepareBaseConfig();
            if (!testCertificateChain(baseConfig, new NopX509CertificateModifier())) {
                throw new ProbeException("Base config is already invalid");
            }
            addExtensionToConfig(baseConfig);
            boolean resultValid = testCertificateChain(baseConfig, createValidExtensionModifier());
            boolean resultInvalid = testCertificateChain(baseConfig, createInvalidExtensionModifier());
            return new ExtensionProbeResult(extensionType, resultValid && !resultInvalid);
        } catch (VerifierException | CertificateGeneratorException e) {
            throw new ProbeException("Unable to execute probe", e);
        }
    }

    protected abstract X509CertificateChainConfig prepareBaseConfig();
    protected abstract void addExtensionToConfig(X509CertificateChainConfig config);
    protected abstract X509CertificateModifier createValidExtensionModifier();
    protected abstract X509CertificateModifier createInvalidExtensionModifier();

    protected boolean testCertificateChain(X509CertificateChainConfig config, X509CertificateModifier modifier) throws CertificateGeneratorException, VerifierException {
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(config);
        certificateChainGenerator.addModifier(modifier);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateChain = certificateChainGenerator.retrieveCertificateChain();

        TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
        VerifierAdapter verifierAdapter = VerifierAdapterFactory.getInstance(testConfig.getVerifierAdapterType(), testConfig.getVerifierAdapterConfig());
        VerifierResult verifierResult = verifierAdapter.invokeVerifier(certificateChain, config);
        return verifierResult.isValid();
    }
}