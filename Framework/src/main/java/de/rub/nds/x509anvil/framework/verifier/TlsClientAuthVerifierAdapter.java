/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.verifier;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.ConfigCache;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.io.IOException;
import java.util.List;

public class TlsClientAuthVerifierAdapter implements VerifierAdapter {
    private static final ConfigCache defaultConfigCache;

    private final Config config;

    static {
        Config defaultConfig = Config.createConfig();
        defaultConfig.setAutoSelectCertificate(false);
        defaultConfig.setDefaultClientConnection(new OutboundConnection("client", 4433, "localhost"));
        defaultConfig.setClientAuthentication(true);
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
    public VerifierResult invokeVerifier(List<X509Certificate> certificatesChain,
        X509CertificateChainConfig chainConfig) throws VerifierException {
        try {
            byte[] encodedChain = X509Util.encodeCertificateChainForTls(certificatesChain);
            CertificateKeyPair certificateKeyPair = new CertificateKeyPair(encodedChain,
                chainConfig.getEntityCertificateConfig().getKeyPair().getPrivate(),
                chainConfig.getEntityCertificateConfig().getKeyPair().getPublic());
            config.setDefaultExplicitCertificateKeyPair(certificateKeyPair);
        } catch (IOException e) {
            throw new VerifierException("Failed to encode certificate", e);
        }

        // Execute workflow
        WorkflowTrace workflowTrace = buildWorkflowTrace(config);
        State state = new State(config, workflowTrace);
        DefaultWorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();

        return new VerifierResult(workflowTrace.executedAsPlanned());
    }

    private static WorkflowTrace buildWorkflowTrace(Config config) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage(), new CertificateMessage(),
            new CertificateRequestMessage(), new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new SendAction(new CertificateMessage(config),
            new RSAClientKeyExchangeMessage(config), new CertificateVerifyMessage(config),
            new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }
}
