package com.fidd.flowerca.bootstrap;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

public class FirstAdminBootstrapRunner implements ApplicationRunner {

  static final long MAX_CSR_BYTES = 64 * 1024;

  private final AdminBootstrapProperties properties;
  private final FirstAdminBootstrapService bootstrapService;
  private final CertificateChainPemEncoder pemEncoder;

  public FirstAdminBootstrapRunner(
      AdminBootstrapProperties properties,
      FirstAdminBootstrapService bootstrapService,
      CertificateChainPemEncoder pemEncoder) {
    this.properties = properties;
    this.bootstrapService = bootstrapService;
    this.pemEncoder = pemEncoder;
  }

  @Override
  public void run(ApplicationArguments arguments) {
    Path csrPath = requirePath(properties.getCsrPath(), "Admin CSR path is required");
    Path outputPath =
        requirePath(
            properties.getCertificateChainOutput(),
            "Admin certificate-chain output path is required");
    String csrPem = readCsr(csrPath);
    AdminBootstrapResult result =
        bootstrapService.bootstrap(
            properties.getDisplayName(), properties.getEmail(), csrPem);
    writeCertificateChain(
        outputPath,
        pemEncoder.encode(result.issuedCertificate().fullChain()));
  }

  private String readCsr(Path path) {
    try {
      if (!Files.isRegularFile(path) || Files.size(path) > MAX_CSR_BYTES) {
        throw new AdminBootstrapException("Admin CSR must be a regular file within the size limit");
      }
      byte[] bytes = Files.readAllBytes(path);
      if (bytes.length > MAX_CSR_BYTES) {
        throw new AdminBootstrapException("Admin CSR exceeds the size limit");
      }
      return new String(bytes, StandardCharsets.US_ASCII);
    } catch (IOException exception) {
      throw new AdminBootstrapException("Unable to read admin CSR", exception);
    }
  }

  private void writeCertificateChain(Path path, byte[] pemChain) {
    try {
      Path parent = path.toAbsolutePath().normalize().getParent();
      if (parent == null || !Files.isDirectory(parent)) {
        throw new AdminBootstrapException(
            "Admin certificate-chain output directory does not exist");
      }
      try {
        Files.write(path, pemChain, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
      } catch (FileAlreadyExistsException exception) {
        if (Files.size(path) > pemChain.length || !Arrays.equals(Files.readAllBytes(path), pemChain)) {
          throw new AdminBootstrapException(
              "Admin certificate-chain output already exists with different content");
        }
      }
    } catch (AdminBootstrapException exception) {
      throw exception;
    } catch (IOException exception) {
      throw new AdminBootstrapException("Unable to write admin certificate chain", exception);
    }
  }

  private Path requirePath(Path path, String message) {
    if (path == null) {
      throw new AdminBootstrapException(message);
    }
    return path.toAbsolutePath().normalize();
  }
}
