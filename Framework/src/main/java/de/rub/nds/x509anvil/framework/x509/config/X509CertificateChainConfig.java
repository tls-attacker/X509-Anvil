/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.anvilcore.model.config.AnvilConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class X509CertificateChainConfig implements AnvilConfig {
    // TODO Find more elegant way for handling default values
    private int chainLength = 1;
    private X509CertificateConfig entityCertificateConfig = X509CertificateUtil.getDefaultCertificateConfig(true, "entity");
    private X509CertificateConfig intermediateCertificatesConfig = X509CertificateUtil.getDefaultCertificateConfig(true, "intermediate");
    private X509CertificateConfig rootCertificateConfig = X509CertificateUtil.getDefaultCertificateConfig(true, "root");

    public List<X509CertificateConfig> getCertificateConfigs() {
        List<X509CertificateConfig> certificateConfigList = new ArrayList<>(chainLength);
        if (chainLength >= 1) {
            // Generate at least the entity certificate
            certificateConfigList.add(entityCertificateConfig);
        }
        if (chainLength >= 2) {
            // Generate at least the entity and root certificates
            certificateConfigList.add(0, rootCertificateConfig);
        }
        if (chainLength >= 3) {
            // Generate chainLength-2 intermediate certificates using the same config
            certificateConfigList.addAll(1, Collections.nCopies(chainLength - 2, intermediateCertificatesConfig));
        }
        return certificateConfigList;
    }

    public int getChainLength() {
        return chainLength;
    }

    public void setChainLength(int chainLength) {
        this.chainLength = chainLength;
    }

    public X509CertificateConfig getEntityCertificateConfig() {
        return entityCertificateConfig;
    }

    public X509CertificateConfig getIntermediateCertificatesConfig() {
        return intermediateCertificatesConfig;
    }

    public X509CertificateConfig getRootCertificateConfig() {
        return rootCertificateConfig;
    }

    public void setEntityCertificateConfig(X509CertificateConfig entityCertificateConfig) {
        this.entityCertificateConfig = entityCertificateConfig;
    }

    public void setIntermediateCertificatesConfig(X509CertificateConfig intermediateCertificatesConfig) {
        this.intermediateCertificatesConfig = intermediateCertificatesConfig;
    }

    public void setRootCertificateConfig(X509CertificateConfig rootCertificateConfig) {
        this.rootCertificateConfig = rootCertificateConfig;
    }
}
