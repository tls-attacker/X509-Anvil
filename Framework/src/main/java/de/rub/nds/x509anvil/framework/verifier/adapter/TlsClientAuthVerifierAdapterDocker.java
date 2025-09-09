package de.rub.nds.x509anvil.framework.verifier.adapter;

import com.github.dockerjava.api.model.AccessMode;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Volume;
import de.rub.nds.tls.subject.ServerUtil;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerInstance;
import de.rub.nds.tls.subject.exceptions.TlsVersionNotFoundException;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfigDocker;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class TlsClientAuthVerifierAdapterDocker extends TlsClientAuthVerifierAdapter {
    protected static final Logger LOGGER = LogManager.getLogger();

    private final static Map<String, DockerTlsServerInstance> tlsServerInstances = new HashMap<String, DockerTlsServerInstance>();
    private static final ServerUtil serverUtil = new ServerUtil();

    private final DockerTlsServerInstance currentServerInstance;

    private TlsClientAuthVerifierAdapterDocker(DockerTlsServerInstance instance) {
        super("localhost", instance.getPort());
        this.currentServerInstance = instance;
    }

    public static TlsClientAuthVerifierAdapterDocker fromConfig(TlsAuthVerifierAdapterConfigDocker config) {
        DockerTlsServerInstance instance = spinUpServer(config);
        return new TlsClientAuthVerifierAdapterDocker(instance);
    }

    private static DockerTlsServerInstance spinUpServer(TlsAuthVerifierAdapterConfigDocker config) {
        String key = config.getImage()+":"+config.getVersion();
        if(tlsServerInstances.containsKey(key)) {
            return tlsServerInstances.get(key);
        }

        String hostname = config.getHostname();

        DockerTlsServerInstance tlsServerInstance = null;
        LOGGER.info("Attempting to start TLS Server Docker image...");
        try {
            tlsServerInstance = DockerTlsManagerFactory.
                    getTlsServerBuilder(TlsImplementationType.fromString(config.getImage()), config.getVersion())
                    .hostConfigHook(TlsClientAuthVerifierAdapterDocker::applyConfig)
                    .cmd(supplementStartCommand(TlsImplementationType.fromString(config.getImage())))
                    .build();
        } catch (TlsVersionNotFoundException e) {
            LOGGER.error("Unknown Version {} of {}", config.getVersion(), config.getImage());
            System.exit(-1);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        tlsServerInstance.start();
        serverUtil.waitUntilServerIsOnline(hostname, tlsServerInstance.getPort());
        config.setPort(tlsServerInstance.getPort());
        tlsServerInstances.put(key, tlsServerInstance);
        return tlsServerInstance;
    }

    private static HostConfig applyConfig(HostConfig config) {
        String hostPath = Paths.get("X509-Testsuite/resources/").toAbsolutePath().toString();
        config.withBinds(new Bind(hostPath, new Volume("/x509-anv-resources/"), AccessMode.ro));
        config.withAutoRemove(true);
        return config;
    }

    private static String[] supplementStartCommand(TlsImplementationType tlsImplementationType) {
        return (switch (tlsImplementationType) {
            case OPENSSL -> "-cert /x509-anv-resources/static-root/root-cert.pem -key /x509-anv-resources/static-root/private-key.pem -CAfile /x509-anv-resources/out/root_cert.pem -Verify 5 -verify_return_error";
            default -> "";
        }).split(" ");
    }

    @Override
    public void runCommandInBackground() {
        if(!serverUtil.isServerOnline(currentServerInstance.getHostInfo().getHostname(), currentServerInstance.getPort())) {
            System.exit(0);
            currentServerInstance.restart();
            serverUtil.waitUntilServerIsOnline(currentServerInstance.getHostInfo().getHostname(), currentServerInstance.getPort());
        }
    }

    public static void stopContainers() {
        for(DockerTlsServerInstance instance : tlsServerInstances.values()) {
            instance.kill();
        }
    }
}
