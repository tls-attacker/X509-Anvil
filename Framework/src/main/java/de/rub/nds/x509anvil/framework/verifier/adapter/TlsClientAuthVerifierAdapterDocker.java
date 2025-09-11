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
import de.rub.nds.tls.subject.ServerUtil;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerInstance;
import de.rub.nds.tls.subject.exceptions.TlsVersionNotFoundException;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfigDocker;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsClientAuthVerifierAdapterDocker extends TlsClientAuthVerifierAdapter {
    protected static final Logger LOGGER = LogManager.getLogger();

    private static final Map<String, DockerTlsServerInstance> tlsServerInstances =
            new HashMap<String, DockerTlsServerInstance>();
    private static final ServerUtil serverUtil = new ServerUtil();

    private final DockerTlsServerInstance currentServerInstance;

    private TlsClientAuthVerifierAdapterDocker(DockerTlsServerInstance instance) {
        super("localhost", instance.getPort());
        this.currentServerInstance = instance;
    }

    public static TlsClientAuthVerifierAdapterDocker fromConfig(
            TlsAuthVerifierAdapterConfigDocker config) {
        DockerTlsServerInstance instance = spinUpServer(config);
        return new TlsClientAuthVerifierAdapterDocker(instance);
    }

    private static DockerTlsServerInstance spinUpServer(TlsAuthVerifierAdapterConfigDocker config) {
        String key = config.getImage() + ":" + config.getVersion();
        if (tlsServerInstances.containsKey(key)) {
            return tlsServerInstances.get(key);
        }

        String hostname = config.getHostname();

        DockerTlsServerInstance tlsServerInstance = null;
        LOGGER.info("Attempting to start TLS Server Docker image...");
        try {
            DockerTlsManagerFactory.TlsServerInstanceBuilder builder =
                    DockerTlsManagerFactory.getTlsServerBuilder(
                                    TlsImplementationType.fromString(config.getImage()),
                                    config.getVersion())
                            .hostConfigHook(TlsClientAuthVerifierAdapterDocker::applyConfig)
                            .additionalParameters(
                                    supplementStartCommand(
                                            TlsImplementationType.fromString(config.getImage())));
            builder.getImageProperties()
                    .setDefaultCertPath("/x509-anv-resources/static-root/root-cert.pem");
            builder.getImageProperties()
                    .setDefaultKeyPath("/x509-anv-resources/static-root/private-key.pem");
            if (TlsImplementationType.fromString(config.getImage())
                    == TlsImplementationType.GNUTLS) {
                builder.getProfile().getParameterList().remove(1);
            }
            tlsServerInstance = builder.build();
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

    private static String supplementStartCommand(TlsImplementationType tlsImplementationType) {
        return (switch (tlsImplementationType) {
            case OPENSSL ->
                    "-CAfile /x509-anv-resources/out/root_cert.pem -Verify 5 -verify_return_error";
            case WOLFSSL -> "-A /x509-anv-resources/out/root_cert.pem";
            default -> "";
        });
    }

    @Override
    public void runCommandInBackground() {
        if (!serverUtil.isServerOnline(
                currentServerInstance.getHostInfo().getHostname(),
                currentServerInstance.getPort())) {
            currentServerInstance.restart();
            serverUtil.waitUntilServerIsOnline(
                    currentServerInstance.getHostInfo().getHostname(),
                    currentServerInstance.getPort());
        }
    }

    public static void stopContainers() {
        for (DockerTlsServerInstance instance : tlsServerInstances.values()) {
            try {
                instance.kill();
            } catch (NotFoundException | InternalServerErrorException e) {
                // Container is already dead, so it's alright :-)
            }
        }
    }
}
