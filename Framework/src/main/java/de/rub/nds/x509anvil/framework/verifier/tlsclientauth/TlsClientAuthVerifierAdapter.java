/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.verifier.tlsclientauth;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.ConfigCache;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TlsClientAuthVerifierAdapter implements VerifierAdapter {
    private static final ConfigCache defaultConfigCache;

    private final Config config;

    static {
        Config defaultConfig = Config.createConfig();
        defaultConfig.setAutoSelectCertificate(false);
        defaultConfig.setDefaultClientConnection(new OutboundConnection("client", 4433, "localhost"));
        defaultConfig.setClientAuthentication(true);


        List<CipherSuite> supportedCipherSuites = new ArrayList<>();
        supportedCipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);

        supportedCipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);

        supportedCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        defaultConfig.setDefaultClientSupportedCipherSuites(supportedCipherSuites);

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
        defaultConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(supportedSignatureAndHashAlgorithms);

        List<NamedGroup> supportedNamedGroups = Arrays.stream(NamedGroup.values())
                .filter(g -> g.name().contains("SECP256R"))
                .collect(Collectors.toList());
        defaultConfig.setDefaultClientNamedGroups(supportedNamedGroups);

        defaultConfig.setAddRenegotiationInfoExtension(false);

        defaultConfigCache = new ConfigCache(defaultConfig);
    }

    public static TlsClientAuthVerifierAdapter fromConfig(TlsClientAuthVerifierAdapterConfig config) {
        String hostname = config.getHostname();
        int port = config.getPort();
        return new TlsClientAuthVerifierAdapter(hostname, port);
    }

    public TlsClientAuthVerifierAdapter(String hostname, int port) {
        config = defaultConfigCache.getCachedCopy();
        config.setDefaultClientConnection(new OutboundConnection("client", port, hostname));
    }

    public TlsClientAuthVerifierAdapter() {
        config = defaultConfigCache.getCachedCopy();
    }

    @Override
    public VerifierResult invokeVerifier(List<X509Certificate> certificatesChain, X509CertificateChainConfig chainConfig) throws VerifierException {
        X509CertificateConfig entityConfig = chainConfig.getEntityCertificateConfig();
        try {
            byte[] encodedChain = X509Util.encodeCertificateChainForTls(certificatesChain);
            CertificateKeyPair certificateKeyPair = new CertificateKeyPair(encodedChain,
                    entityConfig.getKeyPair().getPrivate(),
                    entityConfig.getKeyPair().getPublic());
            config.setDefaultExplicitCertificateKeyPair(certificateKeyPair);
        } catch (IOException e) {
            throw new VerifierException("Failed to encode certificate", e);
        }

        config.setDefaultSelectedSignatureAndHashAlgorithm(TlsAttackerUtil.translateSignatureAlgorithm(entityConfig.getSignatureAlgorithm()));
        config.setAutoAdjustSignatureAndHashAlgorithm(false);

        // Execute workflow
        WorkflowTrace workflowTrace = buildWorkflowTraceRsa(config);
        State state = new State(config, workflowTrace);
        DefaultWorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();

        return new VerifierResult(workflowTrace.executedAsPlanned());
    }

    private static WorkflowTrace buildWorkflowTraceDhe(Config config) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage(), new CertificateMessage(), new DHEServerKeyExchangeMessage(),
            new CertificateRequestMessage(), new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new SendAction(new CertificateMessage(config),
            new DHClientKeyExchangeMessage(config), new CertificateVerifyMessage(config),
            new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }

    private static WorkflowTrace buildWorkflowTraceRsa(Config config) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(
                new ClientHelloMessage(config)
        ));
        workflowTrace.addTlsAction(new ReceiveAction(
                new ServerHelloMessage(),
                new CertificateMessage(),
                new CertificateRequestMessage(),
                new ServerHelloDoneMessage()
        ));
        workflowTrace.addTlsAction(new SendAction(
                new CertificateMessage(config),
                new RSAClientKeyExchangeMessage(config),
                new CertificateVerifyMessage(config),
                new ChangeCipherSpecMessage(config),
                new FinishedMessage(config)
        ));
        workflowTrace.addTlsAction(new ReceiveAction(
                new ChangeCipherSpecMessage(),
                new FinishedMessage()
        ));
        return workflowTrace;
    }
}
