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
import de.rub.nds.x509anvil.framework.x509.generator.NopX509CertificateModifier;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;

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
        config.getEntityCertificateConfig().setIncludeExtensions(true);
        BasicConstraintsConfig extensionConfig = new BasicConstraintsConfig();
        extensionConfig.setPresent(true);
        extensionConfig.setCritical(true);
        extensionConfig.setCa(true);
        extensionConfig.setPathLenConstraintPresent(false);
        config.getEntityCertificateConfig().addExtensions(extensionConfig);
    }

    @Override
    protected X509CertificateModifier createValidExtensionModifier() {
        // Extension is already valid
        return new NopX509CertificateModifier();
    }

    // TODO: no usage?
    /*
    @Override
    protected X509CertificateModifier createInvalidExtensionModifier() {
        return (certificate, config, previousConfig) -> {
            if (config == chainConfig.getEntityCertificateConfig()) {
                X509Util.getExtensionByOid(certificate, BASIC_CONSTRAINTS).setContent(new byte[] { 0x05, 0x00 });
            }
        };
    }
     */
}
