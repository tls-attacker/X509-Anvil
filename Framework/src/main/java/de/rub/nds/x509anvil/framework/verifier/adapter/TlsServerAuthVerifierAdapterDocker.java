package de.rub.nds.x509anvil.framework.verifier.adapter;

import com.fasterxml.jackson.databind.deser.impl.CreatorCandidate;
import com.github.dockerjava.api.command.ExecCreateCmdResponse;
import com.github.dockerjava.api.model.AccessMode;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Volume;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.ServerUtil;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.DockerExecInstance;
import de.rub.nds.tls.subject.docker.DockerTlsClientInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerInstance;
import de.rub.nds.tls.subject.exceptions.TlsVersionNotFoundException;
import de.rub.nds.tls.subject.params.Parameter;
import de.rub.nds.tls.subject.params.ParameterProfileManager;
import de.rub.nds.tls.subject.properties.ImageProperties;
import de.rub.nds.tls.subject.properties.PropertyManager;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfigDocker;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;


public class TlsServerAuthVerifierAdapterDocker extends TlsServerAuthVerifierAdapter {
    protected static final Logger LOGGER = LogManager.getLogger();

    private final static Map<String, DockerTlsClientInstance> tlsClientInstances = new HashMap<String, DockerTlsClientInstance>();
    private static final ServerUtil serverUtil = new ServerUtil();

    private final DockerTlsClientInstance currentClientInstance;
    private int port;

    private TlsServerAuthVerifierAdapterDocker(DockerTlsClientInstance instance) {
        super("localhost", 45655);
        this.currentClientInstance = instance;
        this.port = 45655;
    }

    public static TlsServerAuthVerifierAdapterDocker fromConfig(TlsAuthVerifierAdapterConfigDocker config) {
        DockerTlsClientInstance instance = spinUpServer(config);
        return new TlsServerAuthVerifierAdapterDocker(instance);
    }

    private static DockerTlsClientInstance spinUpServer(TlsAuthVerifierAdapterConfigDocker config) {
        String key = config.getImage()+":"+config.getVersion();
        if(tlsClientInstances.containsKey(key)) {
            return tlsClientInstances.get(key);
        }

        DockerTlsClientInstance tlsClientInstance = null;
        LOGGER.info("Attempting to start TLS Server Docker image...");
        try {
            DockerTlsManagerFactory.TlsClientInstanceBuilder builder = DockerTlsManagerFactory.
                    getTlsClientBuilder(TlsImplementationType.fromString(config.getImage()), config.getVersion())
                    .hostConfigHook(TlsServerAuthVerifierAdapterDocker::applyConfig);
                    //.cmd(supplementStartCommand(TlsImplementationType.fromString(config.getImage())));
            builder.getImageProperties().setDefaultCertPath("/x509-anv-resources/out/root_cert.pem");

            tlsClientInstance = builder.build();
        } catch (TlsVersionNotFoundException e) {
            LOGGER.error("Unknown Version {} of {}", config.getVersion(), config.getImage());
            System.exit(-1);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        tlsClientInstance.start();
        tlsClientInstances.put(key, tlsClientInstance);
        return tlsClientInstance;
    }

    private static HostConfig applyConfig(HostConfig config) {
        String hostPath = Paths.get("X509-Testsuite/resources/").toAbsolutePath().toString();
        config.withBinds(new Bind(hostPath, new Volume("/x509-anv-resources/"), AccessMode.ro));
        config.withExtraHosts("host.docker.internal:host-gateway");

        config.withAutoRemove(true);
        return config;
    }

    private static String[] supplementStartCommand(TlsImplementationType tlsImplementationType) {
        return (switch (tlsImplementationType) {
            default -> "";
        }).split(" ");
    }

    @Override
    public void runCommandInBackground() {
        currentClientInstance.connect("host.docker.internal", this.port);
    }

    public static void stopContainers() {
        for(DockerTlsClientInstance instance : tlsClientInstances.values()) {
            instance.kill();
        }
    }
}
