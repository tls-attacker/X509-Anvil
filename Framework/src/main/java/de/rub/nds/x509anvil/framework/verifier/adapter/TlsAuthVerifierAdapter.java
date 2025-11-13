/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier.adapter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public abstract class TlsAuthVerifierAdapter implements VerifierAdapter {
    private static final Config defaultConfig;

    protected final Config config;

    static {
        Config config = new Config();
        config.setAutoAdjustCertificate(false);

        List<CipherSuite> supportedCipherSuites = new ArrayList<>();
        supportedCipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        config.setDefaultClientSupportedCipherSuites(supportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(supportedCipherSuites);

        List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = new ArrayList<>();
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_MD5);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA1);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA224);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_MD5);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA1);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA224);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA256);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA384);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA512);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_MD5);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA1);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA224);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        supportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                supportedSignatureAndHashAlgorithms);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                supportedSignatureAndHashAlgorithms);

        defaultConfig = config;
    }

    public TlsAuthVerifierAdapter() {
        config = defaultConfig.createCopy();
    }

    @Override
    public VerifierResult invokeVerifier(
            X509CertificateConfig leafCertificateConfig, List<X509Certificate> certificatesChain) {
        List<CertificateBytes> encodedCertificateChain = new LinkedList<>();
        Collections.reverse(certificatesChain);
        for (X509Certificate x509Certificate : certificatesChain) {
            encodedCertificateChain.add(
                    new CertificateBytes(
                            x509Certificate
                                    .getSerializer(new X509Chooser(null, new X509Context()))
                                    .serialize()));
        }

        config.setDefaultExplicitCertificateChain(encodedCertificateChain);
        // adjust proposed signature algorithm to the one used in the certificate
        adjustSignatureAndHashAlgorithm(certificatesChain);

        // Execute workflow
        WorkflowTrace workflowTrace = buildWorkflowTraceDhe(config);
        State state = new State(config, workflowTrace);

        // set keys in tls attacker state
        X509Context x509Context = state.getContext().getTlsContext().getTalkingX509Context();
        x509Context.setSubjectRsaModulus(leafCertificateConfig.getDefaultSubjectRsaModulus());
        x509Context.setSubjectRsaPublicExponent(
                leafCertificateConfig.getDefaultSubjectRsaPublicExponent());
        x509Context.setSubjectRsaPrivateExponent(
                leafCertificateConfig.getDefaultSubjectRsaPrivateExponent());

        x509Context.setSubjectDsaGeneratorG(leafCertificateConfig.getDefaultSubjectDsaGenerator());
        x509Context.setSubjectDsaPublicKeyY(leafCertificateConfig.getDefaultSubjectDsaPublicKey());
        x509Context.setSubjectDsaPrimeModulusP(leafCertificateConfig.getDefaultSubjectDsaPrimeP());
        x509Context.setSubjectDsaPrimeDivisorQ(leafCertificateConfig.getDefaultSubjectDsaPrimeQ());
        x509Context.setSubjectDsaPrivateKeyX(
                leafCertificateConfig.getDefaultSubjectDsaPrivateKey());
        x509Context.setSubjectDsaPrivateK(leafCertificateConfig.getDefaultSubjectDsaNonce());

        x509Context.setSubjectEcPrivateKey(leafCertificateConfig.getDefaultSubjectEcPrivateKey());
        x509Context.setSubjectEcPublicKey(leafCertificateConfig.getDefaultSubjectEcPublicKey());
        x509Context.setSubjectNamedCurve(leafCertificateConfig.getDefaultSubjectNamedCurve());

        DefaultWorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);

        if(this instanceof TlsServerAuthVerifierAdapter) {
            Thread parentThread = Thread.currentThread();
            Thread t =
                    new Thread(
                            () -> {
                                while(!isWaitingInAccept(parentThread)) {
                                    try {
                                        Thread.sleep(3);
                                    } catch (InterruptedException e) {
                                        throw new RuntimeException(e);
                                    }
                                }
                                runCommandInBackground();
                            });
            workflowExecutor.setBeforeTransportInitCallback(state1 -> {
                if(this instanceof TlsServerAuthVerifierAdapterDocker) {
                    ((TlsServerAuthVerifierAdapterDocker)this).realPort = ((ServerTcpTransportHandler)state1.getContext().getTransportHandler()).getSrcPort();
                }
                t.start();
                return 0;
            });
        } else {
            runCommandInBackground();
        }

        workflowExecutor.executeWorkflow();

        return new VerifierResult(workflowTrace.executedAsPlanned());
    }

    private void adjustSignatureAndHashAlgorithm(List<X509Certificate> certificatesChain) {

        try {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm =
                    switch (certificatesChain
                            .getFirst()
                            .getPublicKeyContainer()
                            .getAlgorithmType()) {
                        case RSA -> SignatureAndHashAlgorithm.RSA_SHA256;
                        case DSA -> SignatureAndHashAlgorithm.DSA_SHA256;
                        case ECDSA -> SignatureAndHashAlgorithm.ECDSA_SHA256;
                        default ->
                                throw new IllegalArgumentException(
                                        "Unsupported public key algorithm: "
                                                + certificatesChain
                                                        .getFirst()
                                                        .getPublicKeyContainer()
                                                        .getAlgorithmType());
                    };
            config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                    config.getDefaultClientSupportedSignatureAndHashAlgorithms().stream()
                            .filter(
                                    algorithm ->
                                            algorithm.getSignatureAlgorithm()
                                                    == signatureAndHashAlgorithm
                                                            .getSignatureAlgorithm())
                            .collect(Collectors.toList()));
        } catch (NoSuchElementException e) {
            // modification removed public key container, this is fine
        }
    }

    private boolean isWaitingInAccept(Thread t) {
        for (StackTraceElement e : t.getStackTrace()) {
            String c = e.getClassName();
            String m = e.getMethodName();
            if (("java.net.ServerSocket".equals(c) && "accept".equals(m)) ||
                (c.startsWith("sun.nio.ch.") && "accept".equals(m)) ||
                (c.startsWith("java.net.") && m.contains("accept"))) {
                return true;
            }
        }
        return false;
    }

    abstract WorkflowTrace buildWorkflowTraceDhe(Config config);

    abstract void runCommandInBackground();
}
