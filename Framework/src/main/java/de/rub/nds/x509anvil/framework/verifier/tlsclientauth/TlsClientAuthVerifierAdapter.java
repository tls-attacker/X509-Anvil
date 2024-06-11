/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.verifier.tlsclientauth;

import de.rub.nds.tlsattacker.core.config.Config;
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
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.preparator.TbsCertificatePreparator;

import java.util.*;
import java.util.stream.Collectors;

public class TlsClientAuthVerifierAdapter implements VerifierAdapter {

    private static final Config defaultConfig;

    private final Config config;

    static {
        Config config = new Config();
        config.setAutoAdjustCertificate(false);
        config.setDefaultClientConnection(new OutboundConnection("client", 4433, "localhost"));
        config.setClientAuthentication(true);

        List<CipherSuite> supportedCipherSuites = new ArrayList<>();
        supportedCipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);

        supportedCipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);

        supportedCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        supportedCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        config.setDefaultClientSupportedCipherSuites(supportedCipherSuites);

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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(supportedSignatureAndHashAlgorithms);

        List<NamedGroup> supportedNamedGroups =
            Arrays.stream(NamedGroup.values()).filter(g -> g.name().contains("SECP256R")).collect(Collectors.toList());
        config.setDefaultClientNamedGroups(supportedNamedGroups);

        config.setAddRenegotiationInfoExtension(false);

        defaultConfig = config;
    }

    public static TlsClientAuthVerifierAdapter fromConfig(TlsClientAuthVerifierAdapterConfig config) {
        String hostname = config.getHostname();
        int port = config.getPort();
        return new TlsClientAuthVerifierAdapter(hostname, port);
    }

    public TlsClientAuthVerifierAdapter(String hostname, int port) {
        config = defaultConfig.createCopy();
        config.setDefaultClientConnection(new OutboundConnection("client", port, hostname));
    }

    public TlsClientAuthVerifierAdapter() {
        config = defaultConfig.createCopy();
    }

    @Override
    public VerifierResult invokeVerifier(List<X509Certificate> certificatesChain,
        X509CertificateChainConfig chainConfig) throws VerifierException {
        X509CertificateConfig entityConfig = chainConfig.getEntityCertificateConfig();
        List<CertificateBytes> encodedCertificateChain = new LinkedList<>();
        Collections.reverse(certificatesChain);
        for (X509Certificate x509Certificate : certificatesChain) {
            de.rub.nds.x509attacker.config.X509CertificateConfig config =
                new de.rub.nds.x509attacker.config.X509CertificateConfig();
            // config.setIncludeIssuerUniqueId(true);
            // config.setIncludeSubjectUniqueId(true);
            // TODO: add extensions
            x509Certificate.getTbsCertificate().setExplicitExtensions(null);
            // config.setIncludeExtensions(true);
            x509Certificate.getPreparator(new X509Chooser(config, new X509Context())).prepare();
            encodedCertificateChain.add(new CertificateBytes(
                x509Certificate.getSerializer(new X509Chooser(config, new X509Context())).serialize()));
        }

        defaultConfig.setDefaultExplicitCertificateChain(encodedCertificateChain);

        defaultConfig.setDefaultSelectedSignatureAndHashAlgorithm(
            TlsAttackerUtil.translateSignatureAlgorithm(entityConfig.getSignatureAlgorithm()));
        defaultConfig.setAutoAdjustSignatureAndHashAlgorithm(false);

        // Execute workflow
        WorkflowTrace workflowTrace = buildWorkflowTraceDhe(defaultConfig);
        State state = new State(defaultConfig, workflowTrace);
        DefaultWorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();

        return new VerifierResult(workflowTrace.executedAsPlanned());
    }

    private static WorkflowTrace buildWorkflowTraceDhe(Config config) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage(), new CertificateMessage(),
            new DHEServerKeyExchangeMessage(), new CertificateRequestMessage(), new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new SendAction(new CertificateMessage(), new DHClientKeyExchangeMessage(),
            new CertificateVerifyMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }

    private static WorkflowTrace buildWorkflowTraceRsa(Config config) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage(), new CertificateMessage(),
            new CertificateRequestMessage(), new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new SendAction(new CertificateMessage(), new RSAClientKeyExchangeMessage(),
            new CertificateVerifyMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }
}
