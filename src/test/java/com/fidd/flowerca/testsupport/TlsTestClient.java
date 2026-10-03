package com.fidd.flowerca.testsupport;

import java.net.Socket;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

/** Fresh SSLContext per client prevents session resumption from masking handshake checks. */
public final class TlsTestClient implements AutoCloseable {

  private final HttpClient http;
  private final AtomicInteger identitySelections = new AtomicInteger();
  private final AtomicInteger chainReads = new AtomicInteger();
  private final AtomicBoolean serverTrusted = new AtomicBoolean();

  public TlsTestClient(String protocol, X509Certificate serverTrustAnchor, Identity identity)
      throws Exception {
    KeyStore trust = TlsTestMaterial.emptyStore();
    trust.setCertificateEntry("server-ca", serverTrustAnchor);
    var trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustFactory.init(trust);
    var trustManager = new ObservingTrustManager((X509ExtendedTrustManager) trustFactory.getTrustManagers()[0]);
    KeyManager[] keyManagers = new KeyManager[0];
    if (identity != null) {
      char[] password = new char[0];
      KeyStore keys = TlsTestMaterial.emptyStore();
      keys.setKeyEntry("client", identity.privateKey(), password,
          identity.chain().toArray(X509Certificate[]::new));
      var keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyFactory.init(keys, password);
      keyManagers = new KeyManager[] {
          new PresentingKeyManager((X509ExtendedKeyManager) keyFactory.getKeyManagers()[0])};
    }
    var context = SSLContext.getInstance("TLS");
    context.init(keyManagers, new TrustManager[] {trustManager}, null);
    var parameters = new SSLParameters();
    parameters.setProtocols(new String[] {protocol});
    parameters.setEndpointIdentificationAlgorithm("HTTPS");
    http = HttpClient.newBuilder().sslContext(context).sslParameters(parameters)
        .connectTimeout(Duration.ofSeconds(10)).version(HttpClient.Version.HTTP_1_1).build();
  }

  public HttpClient http() { return http; }
  public int identitySelections() { return identitySelections.get(); }
  public int chainReads() { return chainReads.get(); }
  public boolean serverTrusted() { return serverTrusted.get(); }

  @Override
  public void close() { http.close(); }

  public record Identity(PrivateKey privateKey, List<X509Certificate> chain) {
    public Identity { chain = List.copyOf(chain); }
    @Override
    public String toString() { return "Identity[development-only, chainSize=" + chain.size() + "]"; }
  }

  private final class PresentingKeyManager extends X509ExtendedKeyManager {
    private final X509ExtendedKeyManager delegate;
    private final String alias;
    private PresentingKeyManager(X509ExtendedKeyManager delegate) {
      this.delegate = delegate;
      String[] aliases = delegate.getClientAliases("RSA", null);
      if (aliases == null || aliases.length != 1) {
        throw new IllegalStateException("Expected one RSA test client identity");
      }
      alias = aliases[0];
    }

    @Override
    public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) {
      // Intentionally ignore the server's advertised CA list: a foreign certificate MUST be
      // selected, not silently omitted under client-auth=want. Only this test client is changed.
      identitySelections.incrementAndGet();
      return alias;
    }
    @Override
    public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) {
      identitySelections.incrementAndGet();
      return alias;
    }
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
      chainReads.incrementAndGet();
      return delegate.getCertificateChain(alias);
    }
    @Override
    public PrivateKey getPrivateKey(String alias) { return delegate.getPrivateKey(alias); }
    @Override
    public String[] getClientAliases(String type, Principal[] issuers) { return delegate.getClientAliases(type, issuers); }
    @Override
    public String[] getServerAliases(String type, Principal[] issuers) { return delegate.getServerAliases(type, issuers); }
    @Override
    public String chooseServerAlias(String type, Principal[] issuers, Socket socket) {
      return delegate.chooseServerAlias(type, issuers, socket);
    }
    @Override
    public String chooseEngineServerAlias(String type, Principal[] issuers, SSLEngine engine) {
      return delegate.chooseEngineServerAlias(type, issuers, engine);
    }
  }

  private final class ObservingTrustManager extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager delegate;
    private ObservingTrustManager(X509ExtendedTrustManager delegate) { this.delegate = delegate; }
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String type, SSLEngine engine) throws CertificateException {
      delegate.checkServerTrusted(chain, type, engine);
      serverTrusted.set(true);
    }
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String type, Socket socket) throws CertificateException {
      delegate.checkServerTrusted(chain, type, socket);
      serverTrusted.set(true);
    }
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String type) throws CertificateException {
      delegate.checkServerTrusted(chain, type);
      serverTrusted.set(true);
    }
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String type, SSLEngine engine) throws CertificateException {
      delegate.checkClientTrusted(chain, type, engine);
    }
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String type, Socket socket) throws CertificateException {
      delegate.checkClientTrusted(chain, type, socket);
    }
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String type) throws CertificateException {
      delegate.checkClientTrusted(chain, type);
    }
    @Override
    public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
  }
}
