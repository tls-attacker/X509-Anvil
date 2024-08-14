/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.CertificateChainPositionType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainConfig {
    private static final Logger LOGGER = LogManager.getLogger();

    private int chainLength;
    private int intermediateCertsModeled;

    // TODO: can this be removed? before a static file was read for static root and a certificate generated for not
    // static root. I think we can use the config now for all cases(?)
    // private boolean staticRoot;

    private X509CertificateConfig rootCertificateConfig = null;
    private final List<X509CertificateConfig> intermediateCertificateConfigs = new ArrayList<>();
    private X509CertificateConfig entityCertificateConfig = null;

    private boolean initialized = false;

    public void initializeChain(int chainLength, int intermediateCertsModeled) {
        if (initialized) {
            throw new IllegalStateException("Config is already initialized");
        }

        this.chainLength = chainLength;
        this.intermediateCertsModeled = intermediateCertsModeled;

        TestConfig testConfig = ContextHelper.getTestConfig();

        // TODO: only used in one instance, probably generate certificate once and cache, if annotation present generate
        // new one?
        // this.staticRoot = staticRoot;

        /*
         * if (staticRoot) { try { rootCertificateConfig = X509CertificateConfigUtil.loadStaticCertificateConfig(
         * testConfig.getStaticRootCertificateFile(), testConfig.getStaticRootPrivateKeyFile()); } catch (IOException |
         * InvalidKeySpecException e) { LOGGER.error("Unable to load static root certificate and its private key", e);
         * throw new IllegalArgumentException("Unable to load static root certificate and its private key", e); } } else
         * { // We need to generate our own root rootCertificateConfig =
         * X509CertificateConfigUtil.getDefaultCaCertificateConfig(true, CertificateChainPositionType.ROOT); }
         */
        rootCertificateConfig =
            X509CertificateConfigUtil.getDefaultCaCertificateConfig(true, CertificateChainPositionType.ROOT);

        // Generate configs for intermediate certificates
        for (int i = 0; i < chainLength - 2; i++) {
            if (i < intermediateCertsModeled) {
                X509CertificateConfig config = X509CertificateConfigUtil.getDefaultCaCertificateConfig(false,
                    CertificateChainPositionType.INTERMEDIATE);
                // TODO: can be deleted?
                // if (i == intermediateCertsModeled - 1 && intermediateCertsModeled < chainLength - 2) {
                // config.setSharedConfig(true);
                // }
                intermediateCertificateConfigs.add(config);
            }
        }

        // Generate entity config
        if (chainLength == 1) {
            entityCertificateConfig = rootCertificateConfig;
        } else {
            entityCertificateConfig =
                X509CertificateConfigUtil.getDefaultCertificateConfig(false, CertificateChainPositionType.ENTITY);
        }

        initialized = true;
    }

    public int getChainLength() {
        return chainLength;
    }

    public X509CertificateConfig getEntityCertificateConfig() {
        return entityCertificateConfig;
    }

    public X509CertificateConfig getRootCertificateConfig() {
        return rootCertificateConfig;
    }

    public List<X509CertificateConfig> getIntermediateCertificateConfigs() {
        return intermediateCertificateConfigs;
    }

    public X509CertificateConfig getIntermediateConfig(int index) {
        return intermediateCertificateConfigs.get(index);
    }

    public X509CertificateConfig getIssuerConfigOf(X509CertificateConfig subject) {
        List<X509CertificateConfig> certificateConfigList = getCertificateConfigList();
        if (!certificateConfigList.contains(subject)) {
            throw new IllegalArgumentException("Subject config is not part of the chain");
        }
        if (certificateConfigList.indexOf(subject) == 0) {
            if (subject.isSelfSigned()) {
                return subject;
            }
            throw new IllegalArgumentException("Subject config is root config and not self-signed");
        }

        return certificateConfigList.get(certificateConfigList.indexOf(subject) - 1);
    }

    public List<X509CertificateConfig> getCertificateConfigList() {
        List<X509CertificateConfig> certificateConfigList = new ArrayList<>();

        if (chainLength == 0) {
            return certificateConfigList;
        } else if (chainLength == 1) {
            certificateConfigList.add(rootCertificateConfig);
            return certificateConfigList;
        } else {
            certificateConfigList.add(rootCertificateConfig);
            certificateConfigList.addAll(intermediateCertificateConfigs);
            certificateConfigList.add(entityCertificateConfig);
            return certificateConfigList;
        }

    }

    public int getIntermediateCertsModeled() {
        return intermediateCertsModeled;
    }

    public boolean isInitialized() {
        return initialized;
    }
}
