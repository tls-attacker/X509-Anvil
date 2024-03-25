/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.model.*;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.x509.model.Extension;

public abstract class ExtensionConfig {
    private final String extensionId;
    private final String name;
    private boolean present = false;
    private boolean critical = false;

    public ExtensionConfig(String extensionId, String name) {
        this.extensionId = extensionId;
        this.name = name;
    }

    public boolean isPresent() {
        return present;
    }

    public void setPresent(boolean present) {
        this.present = present;
    }

    public boolean isCritical() {
        return critical;
    }

    public void setCritical(boolean critical) {
        this.critical = critical;
    }

    public Extension getExtensionFromConfig(X509CertificateConfig certificateConfig,
        X509CertificateConfig previousConfig) throws CertificateGeneratorException {
        Extension extensionAsn1 = new Extension(name);

        Asn1ObjectIdentifier extnIdAsn1 = new Asn1ObjectIdentifier("extnId");
        extnIdAsn1.setValue(extensionId);
        extensionAsn1.setExtnID(extnIdAsn1);

        if (critical) {
            Asn1Boolean criticalAsn1 = new Asn1Boolean("critical");
            criticalAsn1.setValue(critical);
            extensionAsn1.setCritical(criticalAsn1);
        }

        Asn1OctetString extnValueAsn1 = getContentAsn1Structure(certificateConfig, previousConfig);
        extnValueAsn1.setIdentifier("extnValue");
        extensionAsn1.setExtnValue(extnValueAsn1);

        return extensionAsn1;
    }

    protected abstract Asn1OctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
        X509CertificateConfig previousConfig) throws CertificateGeneratorException;
}
