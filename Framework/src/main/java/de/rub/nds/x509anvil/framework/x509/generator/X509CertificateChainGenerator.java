/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

public class X509CertificateChainGenerator {
    private final X509CertificateChainConfig certificateChainConfig;

    // TODO: should be used, but can probably also simplified

    private final List<X509Certificate> generatedCertificates = new ArrayList<>();

    public X509CertificateChainGenerator(X509CertificateChainConfig certificateChainConfig) {
        this.certificateChainConfig = certificateChainConfig;
    }

    public void generateCertificateChain() throws CertificateGeneratorException {
        if (!certificateChainConfig.isInitialized()) {
            throw new CertificateGeneratorException(
                    "X509CertificateChainConfig is not initialized");
        }

        X509CertificateConfig signerConfig = null;

        // set signature signing keys to keys from signer config unless self-signed

        for (int i = 0;
                i < certificateChainConfig.getCertificateConfigList().toArray().length;
                i++) {
            X509CertificateConfig config = certificateChainConfig.getCertificateConfigList().get(i);

            if (config.isSelfSigned()) {
                config.setIssuer(config.getSubject());
            }

            if (signerConfig != null && !config.isSelfSigned()) {

                // copy issuer without modifications
                List<Pair<X500AttributeType, String>> signerSubject = new ArrayList<>();
                AtomicBoolean containsCountry = new AtomicBoolean(false);
                X509CertificateConfig finalSignerConfig = signerConfig;
                signerConfig
                        .getSubject()
                        .forEach(
                                pair -> {
                                    String value = pair.getValue();
                                    if (value.contains("_modified")) {
                                        // mismatch tests
                                        value = value.replace("_modified", "");
                                    }
                                    if (pair.getKey() == X500AttributeType.DOMAIN_COMPONENT
                                            && finalSignerConfig
                                                    .isSubjectDomainComponentCaseInsensitive()) {
                                        value = value.toLowerCase(Locale.ROOT);
                                    }
                                    if (!value.contains(
                                            "additional_rdn")) { // additional rdn mismatch test
                                        signerSubject.add(new Pair<>(pair.getKey(), value));
                                    }
                                    if (pair.getKey() == X500AttributeType.COUNTRY_NAME) {
                                        containsCountry.set(true);
                                    }
                                });

                // removed country modification
                if (!containsCountry.get()) {
                    signerSubject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
                }

                List<Pair<X500AttributeType, String>> shuffledSignerSubject =
                        new ArrayList<>(signerSubject);
                if (config.isShuffleIssuer()) {
                    while (shuffledSignerSubject.equals(signerSubject)) {
                        Collections.shuffle(shuffledSignerSubject);
                    }
                }

                if (config.isRemoveFirstRdnIssuer()) {
                    shuffledSignerSubject.removeFirst();
                }

                if (config.isDuplicateFirstRdnIssuer()) {
                    shuffledSignerSubject.add(shuffledSignerSubject.getFirst());
                }

                config.setIssuer(shuffledSignerSubject);

                // copy issuer key type
                config.setDefaultIssuerPublicKeyType(signerConfig.getPublicKeyType());

                // copy keys
                // rsa
                config.setDefaultIssuerRsaModulus(signerConfig.getDefaultSubjectRsaModulus());
                config.setDefaultIssuerRsaPrivateExponent(
                        signerConfig.getDefaultSubjectRsaPrivateExponent());
                config.setDefaultIssuerRsaPublicKey(signerConfig.getDefaultSubjectRsaPublicKey());
                // dsa
                config.setDefaultIssuerDsaGenerator(signerConfig.getDefaultSubjectDsaGenerator());
                config.setDefaultIssuerDsaPublicKey(signerConfig.getDefaultSubjectDsaPublicKey());
                config.setDefaultIssuerDsaPrimeP(signerConfig.getDefaultSubjectDsaPrimeP());
                config.setDefaultIssuerDsaPrimeQ(signerConfig.getDefaultSubjectDsaPrimeQ());
                config.setDefaultIssuerDsaNonce(signerConfig.getDefaultSubjectDsaNonce());
                config.setDefaultIssuerDsaPrivateKey(signerConfig.getDefaultSubjectDsaPrivateKey());
                // ecdsa
                config.setDefaultIssuerEcPrivateKey(signerConfig.getDefaultSubjectEcPrivateKey());
                config.setDefaultIssuerEcPublicKey(signerConfig.getDefaultSubjectEcPublicKey());
                config.setDefaultIssuerNamedCurve(signerConfig.getDefaultSubjectNamedCurve());
                config.setDefaultEcPointFormat(signerConfig.getDefaultEcPointFormat());
                config.setDefaultIssuerEcPrivateKey(signerConfig.getDefaultSubjectEcPrivateKey());
            }

            signerConfig = config;
        }

        for (X509CertificateConfig certificateConfig :
                certificateChainConfig.getCertificateConfigList()) {
            generateSingleCertificate(certificateConfig);
        }
    }

    public List<X509Certificate> retrieveCertificateChain() {
        return this.generatedCertificates;
    }

    private void generateSingleCertificate(X509CertificateConfig config) {
        X509Certificate certificate = new X509Certificate("cert", config);
        this.generatedCertificates.add(certificate);
        certificate.getPreparator(new X509Chooser(config, new X509Context())).prepare();
    }
}
