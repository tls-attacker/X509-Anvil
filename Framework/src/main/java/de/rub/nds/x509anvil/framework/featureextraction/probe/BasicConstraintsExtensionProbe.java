/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.generator.NopX509CertificateModifier;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;

import static de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers.BASIC_CONSTRAINTS;

public class BasicConstraintsExtensionProbe extends ExtensionProbe {
    private X509CertificateChainConfig chainConfig;

    public BasicConstraintsExtensionProbe() {
        super(ExtensionType.BASIC_CONSTRAINTS);
    }

    @Override
    protected X509CertificateChainConfig prepareBaseConfig() {
        chainConfig = X509CertificateConfigUtil.createBasicConfig(2);
        return chainConfig;
    }

    @Override
    protected void addExtensionToConfig(X509CertificateChainConfig config) {
        config.getEntityCertificateConfig().setExtensionsPresent(true);
        BasicConstraintsExtensionConfig extensionConfig = (BasicConstraintsExtensionConfig) config
            .getEntityCertificateConfig().extension(ExtensionType.BASIC_CONSTRAINTS);
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
                certificate.getTbsCertificate().getExplicitExtensions().getInnerField().getExtensionList()
                    .forEach(extension -> {
                        if (extension.getExtnID().getValue().getValue().equals(BASIC_CONSTRAINTS)) {
                            extension.setContent(new byte[] { 0x05, 0x00 });
                        }
                    });
            }
        };
    }
}
