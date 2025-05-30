package de.rub.nds.x509anvil.framework.verifier.adapter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfig;

import java.io.IOException;

public class TlsServerAuthVerifierAdapter extends TlsAuthVerifierAdapter {

    public TlsServerAuthVerifierAdapter(String hostname, int port) {
        super(hostname, port);
        config.setDefaultServerConnection(new InboundConnection("client", port, hostname));
        config.setClientAuthentication(false);
        config.setDefaultRunningMode(RunningModeType.SERVER);
        config.setAddRenegotiationInfoExtension(true);
    }

    public static TlsServerAuthVerifierAdapter fromConfig(TlsAuthVerifierAdapterConfig config) {
        String hostname = config.getHostname();
        int port = config.getPort();
        return new TlsServerAuthVerifierAdapter(hostname, port);
    }

    @Override
    public WorkflowTrace buildWorkflowTraceDhe(Config config) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        //workflowTrace.addTlsAction(new InvokeClientAction());
        workflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        workflowTrace.addTlsAction(new SendAction(new ServerHelloMessage(config), new CertificateMessage(),
                new DHEServerKeyExchangeMessage(), new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new DHClientKeyExchangeMessage(),
                new ChangeCipherSpecMessage(), new FinishedMessage()));
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }

    @Override
    public void runCommandInBackground() {
        Thread commandThread = new Thread(() -> {
            try {
                ProcessBuilder builder = new ProcessBuilder(
                        "openssl", "s_client", "-connect", "127.0.0.1:4433", "-verify_return_error", "-CAfile", "./resources/out/root_cert.pem"
                );

                builder.redirectErrorStream(true);
                Process process = builder.start();

                //TODO: Optional logging via config
                /*try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println("[openssl] " + line);
                    }
                }*/

                process.waitFor();
            } catch (IOException | InterruptedException e) {
                System.err.println("Error executing OpenSSL command: " + e.getMessage());
            }
        });

        commandThread.start(); // Start the thread asynchronously
    }
}
