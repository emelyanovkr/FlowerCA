package com.fidd.flowerca.testsupport;

import java.util.ArrayList;
import java.util.List;
import org.hibernate.resource.jdbc.spi.StatementInspector;

public class CertificateReadSqlInspector implements StatementInspector {
  private static final ThreadLocal<List<String>> CAPTURED = new ThreadLocal<>();

  public static void start() {
    CAPTURED.set(new ArrayList<>());
  }

  public static List<String> finish() {
    var statements = List.copyOf(CAPTURED.get());
    CAPTURED.remove();
    return statements;
  }

  @Override
  public String inspect(String sql) {
    var statements = CAPTURED.get();
    if (statements != null) {
      statements.add(sql);
    }
    return sql;
  }
}
