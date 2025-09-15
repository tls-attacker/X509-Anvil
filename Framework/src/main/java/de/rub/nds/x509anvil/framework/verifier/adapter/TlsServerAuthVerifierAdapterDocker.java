/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier.adapter;

import com.github.dockerjava.api.exception.InternalServerErrorException;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.AccessMode;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Volume;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.DockerTlsClientInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.exceptions.TlsVersionNotFoundException;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfigDocker;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsServerAuthVerifierAdapterDocker extends TlsServerAuthVerifierAdapter {
    protected static final Logger LOGGER = LogManager.getLogger();

    private static final Map<String, DockerTlsClientInstance> tlsClientInstances = new HashMap<>();

    private final DockerTlsClientInstance currentClientInstance;
    private final int port;

    private TlsServerAuthVerifierAdapterDocker(DockerTlsClientInstance instance) {
        super("localhost", 45655);
        this.currentClientInstance = instance;
        this.port = 45655;
    }

    public static TlsServerAuthVerifierAdapterDocker fromConfig(
            TlsAuthVerifierAdapterConfigDocker config) {
        DockerTlsClientInstance instance = spinUpServer(config);
        return new TlsServerAuthVerifierAdapterDocker(instance);
    }

    private static DockerTlsClientInstance spinUpServer(TlsAuthVerifierAdapterConfigDocker config) {
        String key = config.getImage() + ":" + config.getVersion();
        if (tlsClientInstances.containsKey(key)) {
            return tlsClientInstances.get(key);
        }

        DockerTlsClientInstance tlsClientInstance = null;
        LOGGER.info("Attempting to start TLS Server Docker image...");
        try {
            tlsClientInstance =
                    DockerTlsManagerFactory.getTlsClientBuilder(
                                    TlsImplementationType.fromString(config.getImage()),
                                    config.getVersion())
                            .hostConfigHook(TlsServerAuthVerifierAdapterDocker::applyConfig)
                            .certificatePath("/x509-anv-resources/out/root_cert.pem")
                            .build();
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
        config.withExtraHosts("tls-attacker.com:host-gateway");
        config.withAutoRemove(true);
        return config;
    }

    @Override
    public void runCommandInBackground() {
        currentClientInstance.connect("tls-attacker.com", this.port);
    }

    public static void stopContainers() {
        for (DockerTlsClientInstance instance : tlsClientInstances.values()) {
            try {
                instance.kill();
            } catch (NotFoundException | InternalServerErrorException e) {
                // Container is already dead, so it's alright :-)
            }
        }
    }
}
