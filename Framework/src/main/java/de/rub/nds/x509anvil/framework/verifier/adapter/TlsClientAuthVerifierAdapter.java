/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.verifier.adapter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfig;

public class TlsClientAuthVerifierAdapter extends TlsAuthVerifierAdapter {
    public TlsClientAuthVerifierAdapter(String hostname, int port) {
        super(hostname, port);
        config.setDefaultClientConnection(new OutboundConnection("client", 4433, "localhost"));
        config.setClientAuthentication(true);
        config.setAddRenegotiationInfoExtension(false);
    }

    public static TlsClientAuthVerifierAdapter fromConfig(TlsAuthVerifierAdapterConfig config) {
        String hostname = config.getHostname();
        int port = config.getPort();
        return new TlsClientAuthVerifierAdapter(hostname, port);
    }

    @Override
    public WorkflowTrace buildWorkflowTraceDhe(Config config) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage(), new CertificateMessage(),
                new DHEServerKeyExchangeMessage(), new CertificateRequestMessage(), new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new SendAction(new CertificateMessage(), new DHClientKeyExchangeMessage(),
                new CertificateVerifyMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }

    @Override
    public void runCommandInBackground() {
        // nothing to-do for client auth scan
    }
}
