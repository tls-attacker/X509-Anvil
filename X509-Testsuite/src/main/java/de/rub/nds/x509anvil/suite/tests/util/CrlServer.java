package de.rub.nds.x509anvil.suite.tests.util;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class CrlServer {
    private final HttpServer server;
    private final int port;

    public CrlServer(int port) {
        this.port = port;
        try {
            server = HttpServer.create(new InetSocketAddress(port), 0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        server.createContext("/", new Handler());
        server.setExecutor(null); // default executor
    }

    public void start() {
        server.start();
        System.out.println("CRL Server started on http://localhost:" + port);
    }

    public void stop() {
        server.stop(0);
        System.out.println("CRL Server stopped.");
    }

    private static class Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                exchange.close();
                return;
            }

            URI requestURI = exchange.getRequestURI();
            String path = requestURI.getPath(); // e.g. /crls/72.crl

            // Expecting format: /crls/<filename>.crl
            String[] parts = path.split("/");
            if (parts.length != 3 || !"crls".equals(parts[1]) || parts[2].isBlank()) {
                sendText(exchange, "Invalid CRL request. Use /crls/<filename>.crl", 400);
                return;
            }

            String filename = parts[2];

            // Basic validation
            if (!filename.endsWith(".crl") || filename.contains("..") || filename.contains("\\") || filename.contains("/")) {
                sendText(exchange, "Invalid filename", 400);
                return;
            }

            // Base directory decided locally (no field). Example: ./crls
            Path baseDir = Paths.get("resources/crls").toAbsolutePath().normalize();
            Path file = baseDir.resolve(filename).normalize();

            // Prevent path traversal
            if (!file.startsWith(baseDir)) {
                sendText(exchange, "Forbidden", 403);
                return;
            }

            if (!Files.exists(file) || Files.isDirectory(file)) {
                sendText(exchange, "Not found", 404);
                return;
            }

            long size = Files.size(file);

            exchange.getResponseHeaders().set("Content-Type", "application/pkix-crl");
            exchange.getResponseHeaders().set("Content-Disposition",
                    "inline; filename=\"" + filename.replace("\"", "") + "\"");
            exchange.getResponseHeaders().set("Content-Length", Long.toString(size));

            exchange.sendResponseHeaders(200, size);

            try (OutputStream os = exchange.getResponseBody();
                 InputStream is = Files.newInputStream(file, StandardOpenOption.READ)) {
                is.transferTo(os);
            } finally {
                exchange.close();
            }
        }
    }

    private static void sendText(HttpExchange exchange, String response, int statusCode) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        } finally {
            exchange.close();
        }
    }
}
