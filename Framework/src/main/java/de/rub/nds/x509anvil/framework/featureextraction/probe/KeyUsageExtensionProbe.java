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
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.apache.commons.lang3.NotImplementedException;

public class KeyUsageExtensionProbe extends ExtensionProbe {
    private X509CertificateChainConfig chainConfig;

    public KeyUsageExtensionProbe() {
        super(ExtensionType.KEY_USAGE);
    }

    @Override
    protected X509CertificateChainConfig prepareBaseConfig() {
        chainConfig = X509CertificateConfigUtil.createBasicConfig(2);
        return chainConfig;
    }

    @Override
    protected void addExtensionToConfig(X509CertificateChainConfig config) {
        // TODO: re-implement
        /*
         * config.getEntityCertificateConfig().setExtensionsPresent(true); KeyUsageExtensionConfig extensionConfig =
         * (KeyUsageExtensionConfig) config.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE);
         * extensionConfig.setPresent(true); extensionConfig.setCritical(true);
         * extensionConfig.setDigitalSignature(true);
         */

        throw new NotImplementedException("KeyUsageExtension not implemented yet");
    }
}
