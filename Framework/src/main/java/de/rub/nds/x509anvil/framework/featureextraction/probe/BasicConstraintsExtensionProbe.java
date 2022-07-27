package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.x509.X509CertificateUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.generator.NopX509CertificateModifier;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;

public class BasicConstraintsExtensionProbe extends ExtensionProbe {
    private X509CertificateChainConfig chainConfig;

    public BasicConstraintsExtensionProbe() {
        super(ExtensionType.BASIC_CONSTRAINTS);
    }

    @Override
    protected X509CertificateChainConfig prepareBaseConfig() {
        chainConfig = X509CertificateUtil.createBasicConfig(2);
        return chainConfig;
    }

    @Override
    protected void addExtensionToConfig(X509CertificateChainConfig config) {
        config.getEntityCertificateConfig().setExtensionsPresent(true);
        BasicConstraintsExtensionConfig extensionConfig = (BasicConstraintsExtensionConfig)
                config.getEntityCertificateConfig().extension(ExtensionType.BASIC_CONSTRAINTS);
        extensionConfig.setPresent(true);
        extensionConfig.setCritical(true);
        extensionConfig.setCa(true);
        extensionConfig.setPathLenConstraintPresent(false);
    }

    @Override
    protected X509CertificateModifier createValidExtensionModifier() {
        // Extension is already valid
        return new NopX509CertificateModifier();
    }

    @Override
    protected X509CertificateModifier createInvalidExtensionModifier() {
        return (certificate, config, previousConfig) -> {
            if (config == chainConfig.getEntityCertificateConfig()) {
                Asn1PrimitiveOctetString extensionValue = (Asn1PrimitiveOctetString) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "explicitExtensions", "extensions", "basicConstraints", "extnValue");
                extensionValue.setValue(new byte[]{0x02,0x01, (byte)0xff});
            }
        };
    }
}