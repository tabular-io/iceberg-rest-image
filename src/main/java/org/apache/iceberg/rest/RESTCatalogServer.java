/*
 * Copyright 2024 Tabular Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.iceberg.rest;

import org.apache.hadoop.conf.Configuration;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.CatalogUtil;
import org.apache.iceberg.catalog.Catalog;
import org.apache.iceberg.util.PropertyUtil;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class RESTCatalogServer {
  private static final Logger LOG = LoggerFactory.getLogger(RESTCatalogServer.class);
  private static final String CATALOG_ENV_PREFIX = "CATALOG_";
  private static final String HADOOP_ENV_PREFIX = "CATALOG_HADOOP_";

  private RESTCatalogServer() {
  }

  record CatalogContext(Catalog catalog, Map<String, String> configuration) {
  }

  private static CatalogContext backendCatalog() throws IOException {
    // Translate environment variable to catalog properties
    Map<String, String> catalogProperties =
        System.getenv().entrySet().stream()
            .filter(e -> e.getKey().startsWith(CATALOG_ENV_PREFIX))
            .collect(
                Collectors.toMap(
                    e -> envKeyToPropertyKey(e.getKey(), CATALOG_ENV_PREFIX),
                    Map.Entry::getValue,
                    (m1, m2) -> {
                      throw new IllegalArgumentException("Duplicate key: " + m1);
                    },
                    HashMap::new));

    // Fallback to a JDBCCatalog impl if one is not set
    if (!catalogProperties.containsKey(CatalogProperties.CATALOG_IMPL)) {
      catalogProperties.putIfAbsent(CatalogProperties.CATALOG_IMPL, "org.apache.iceberg.jdbc.JdbcCatalog");
      catalogProperties.putIfAbsent(CatalogProperties.URI, "jdbc:sqlite:file:/tmp/iceberg_rest_mode=memory");
      catalogProperties.putIfAbsent("jdbc.user", "user");
      catalogProperties.putIfAbsent("jdbc.password", "password");
      catalogProperties.putIfAbsent("jdbc.schema-version", "V1");
    }

    // Configure a default location if one is not specified
    String warehouseLocation = catalogProperties.get(CatalogProperties.WAREHOUSE_LOCATION);

    if (warehouseLocation == null) {
      File tmp = java.nio.file.Files.createTempDirectory("iceberg_warehouse").toFile();
      tmp.deleteOnExit();
      warehouseLocation = tmp.toPath().resolve("iceberg_data").toFile().getAbsolutePath();
      catalogProperties.put(CatalogProperties.WAREHOUSE_LOCATION, warehouseLocation);

      LOG.info("No warehouse location set.  Defaulting to temp location: {}", warehouseLocation);
    }

    Configuration hadoopConf = new Configuration();

    System.getenv().entrySet().stream()
        .filter(e -> e.getKey().startsWith(HADOOP_ENV_PREFIX))
        .forEach(e -> hadoopConf.set(envKeyToPropertyKey(e.getKey(), HADOOP_ENV_PREFIX), e.getValue()));

    LOG.info("Creating catalog with properties: {}", catalogProperties);

    return new CatalogContext(CatalogUtil.buildIcebergCatalog("rest_backend", catalogProperties, hadoopConf), catalogProperties);
  }

  public static String envKeyToPropertyKey(String key, String prefix) {
    String s = key.
        replaceFirst("^" + Pattern.quote(prefix), "")
        .toLowerCase(Locale.ROOT)
        .replace("__", "-");

    Matcher m = Pattern.compile("_u_([a-z])").matcher(s);
    StringBuilder sb = new StringBuilder();
    while (m.find()) {
      m.appendReplacement(sb, m.group(1).toUpperCase(Locale.ROOT));
    }
    m.appendTail(sb);
    s = sb.toString();
    s = s.replace("_", ".");

    return s;
  }

  public static void main(String[] args) throws Exception {
    CatalogContext catalogContext = backendCatalog();
    try (RESTCatalogAdapter adapter = new RESTServerCatalogAdapter(catalogContext)) {
      RESTCatalogServlet servlet = new RESTCatalogServlet(adapter);

      ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
      context.setContextPath("/");
      ServletHolder servletHolder = new ServletHolder(servlet);
      servletHolder.setInitParameter("javax.ws.rs.Application", "ServiceListPublic");
      context.addServlet(servletHolder, "/*");
      context.setVirtualHosts(null);
      context.insertHandler(new GzipHandler());

      Server httpServer = new Server(PropertyUtil.propertyAsInt(System.getenv(), "REST_PORT", 8181));
      httpServer.setHandler(context);

      httpServer.start();
      httpServer.join();
    }
  }
}
