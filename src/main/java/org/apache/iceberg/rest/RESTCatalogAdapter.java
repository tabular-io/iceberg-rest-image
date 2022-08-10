/*
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

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.CharStreams;
import org.apache.hadoop.conf.Configuration;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.CatalogUtil;
import org.apache.iceberg.catalog.Catalog;
import org.apache.iceberg.catalog.Namespace;
import org.apache.iceberg.catalog.SupportsNamespaces;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.exceptions.AlreadyExistsException;
import org.apache.iceberg.exceptions.CommitFailedException;
import org.apache.iceberg.exceptions.CommitStateUnknownException;
import org.apache.iceberg.exceptions.ForbiddenException;
import org.apache.iceberg.exceptions.NamespaceNotEmptyException;
import org.apache.iceberg.exceptions.NoSuchIcebergTableException;
import org.apache.iceberg.exceptions.NoSuchNamespaceException;
import org.apache.iceberg.exceptions.NoSuchTableException;
import org.apache.iceberg.exceptions.NotAuthorizedException;
import org.apache.iceberg.exceptions.RESTException;
import org.apache.iceberg.exceptions.UnprocessableEntityException;
import org.apache.iceberg.exceptions.ValidationException;
import org.apache.iceberg.rest.requests.CreateNamespaceRequest;
import org.apache.iceberg.rest.requests.CreateTableRequest;
import org.apache.iceberg.rest.requests.RenameTableRequest;
import org.apache.iceberg.rest.requests.UpdateNamespacePropertiesRequest;
import org.apache.iceberg.rest.requests.UpdateTableRequest;
import org.apache.iceberg.rest.responses.ConfigResponse;
import org.apache.iceberg.rest.responses.CreateNamespaceResponse;
import org.apache.iceberg.rest.responses.ErrorResponse;
import org.apache.iceberg.rest.responses.GetNamespaceResponse;
import org.apache.iceberg.rest.responses.ListNamespacesResponse;
import org.apache.iceberg.rest.responses.ListTablesResponse;
import org.apache.iceberg.rest.responses.LoadTableResponse;
import org.apache.iceberg.rest.responses.OAuthTokenResponse;
import org.apache.iceberg.rest.responses.UpdateNamespacePropertiesResponse;
import org.apache.iceberg.util.Pair;
import org.apache.iceberg.util.PropertyUtil;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.lang.String.format;

/**
 * TODO:  This class is borrowed from Apache Iceberg to provide the Servlet implementation for testing
 *        and should be removed when available directly from the iceberg test dependencies.
 * <p>
 * Adaptor class to translate REST requests into {@link Catalog} API calls.
 */
public class RESTCatalogAdapter
        implements RESTClient
{
    private static final Logger LOG = LoggerFactory.getLogger(RESTCatalogAdapter.class);
    private static final Splitter SLASH = Splitter.on('/');

    private static final Map<Class<? extends Exception>, Integer> EXCEPTION_ERROR_CODES = ImmutableMap.<Class<? extends Exception>, Integer>builder()
            .put(IllegalArgumentException.class, 400)
            .put(ValidationException.class, 400)
            .put(NamespaceNotEmptyException.class, 400) // TODO: should this be more specific?
            .put(NotAuthorizedException.class, 401)
            .put(ForbiddenException.class, 403)
            .put(NoSuchNamespaceException.class, 404)
            .put(NoSuchTableException.class, 404)
            .put(NoSuchIcebergTableException.class, 404)
            .put(UnsupportedOperationException.class, 406)
            .put(AlreadyExistsException.class, 409)
            .put(CommitFailedException.class, 409)
            .put(UnprocessableEntityException.class, 422)
            .put(CommitStateUnknownException.class, 500)
            .buildOrThrow();

    private final Catalog catalog;
    private final SupportsNamespaces asNamespaceCatalog;

    public RESTCatalogAdapter(Catalog catalog)
    {
        this.catalog = catalog;
        this.asNamespaceCatalog = catalog instanceof SupportsNamespaces ? (SupportsNamespaces) catalog : null;
    }

    public static <T> T castRequest(Class<T> requestType, Object request)
    {
        if (requestType.isInstance(request)) {
            return requestType.cast(request);
        }

        throw new BadRequestType(requestType, request);
    }

    public static <T extends RESTResponse> T castResponse(Class<T> responseType, Object response)
    {
        if (responseType.isInstance(response)) {
            return responseType.cast(response);
        }

        throw new BadResponseType(responseType, response);
    }

    public static void configureResponseFromException(Exception exc, ErrorResponse.Builder errorBuilder)
    {
        errorBuilder.responseCode(EXCEPTION_ERROR_CODES.getOrDefault(exc.getClass(), 500)).withType(exc.getClass().getSimpleName()).withMessage(exc.getMessage()).withStackTrace(exc);
    }

    private static Namespace namespaceFromPathVars(Map<String, String> pathVars)
    {
        return RESTUtil.decodeNamespace(pathVars.get("namespace"));
    }

    private static TableIdentifier identFromPathVars(Map<String, String> pathVars)
    {
        return TableIdentifier.of(namespaceFromPathVars(pathVars), RESTUtil.decodeString(pathVars.get("table")));
    }

    public <T extends RESTResponse> T handleRequest(Route route, Map<String, String> vars, Object body, Class<T> responseType)
    {
        switch (route) {
            case TOKENS: {
                @SuppressWarnings("unchecked") Map<String, String> request = (Map<String, String>) castRequest(Map.class, body);
                String grantType = request.get("grant_type");
                switch (grantType) {
                    case "client_credentials":
                        return castResponse(responseType, OAuthTokenResponse.builder().withToken("client-credentials-token:sub=" + request.get("client_id")).withIssuedTokenType("urn:ietf:params:oauth:token-type:access_token").withTokenType("Bearer").build());

                    case "urn:ietf:params:oauth:grant-type:token-exchange":
                        String actor = request.get("actor_token");
                        String token = format("token-exchange-token:sub=%s%s", request.get("subject_token"), actor != null ? ",act=" + actor : "");
                        return castResponse(responseType, OAuthTokenResponse.builder().withToken(token).withIssuedTokenType("urn:ietf:params:oauth:token-type:access_token").withTokenType("Bearer").build());

                    default:
                        throw new UnsupportedOperationException("Unsupported grant_type: " + grantType);
                }
            }

            case CONFIG:
                return castResponse(responseType, ConfigResponse.builder().build());

            case LIST_NAMESPACES:
                if (asNamespaceCatalog != null) {
                    Namespace ns;
                    if (vars.containsKey("parent")) {
                        ns = Namespace.of(RESTUtil.NAMESPACE_SPLITTER.splitToStream(vars.get("parent")).toArray(String[]::new));
                    }
                    else {
                        ns = Namespace.empty();
                    }

                    return castResponse(responseType, CatalogHandlers.listNamespaces(asNamespaceCatalog, ns));
                }
                break;

            case CREATE_NAMESPACE:
                if (asNamespaceCatalog != null) {
                    CreateNamespaceRequest request = castRequest(CreateNamespaceRequest.class, body);
                    return castResponse(responseType, CatalogHandlers.createNamespace(asNamespaceCatalog, request));
                }
                break;

            case LOAD_NAMESPACE:
                if (asNamespaceCatalog != null) {
                    Namespace namespace = namespaceFromPathVars(vars);
                    return castResponse(responseType, CatalogHandlers.loadNamespace(asNamespaceCatalog, namespace));
                }
                break;

            case DROP_NAMESPACE:
                if (asNamespaceCatalog != null) {
                    CatalogHandlers.dropNamespace(asNamespaceCatalog, namespaceFromPathVars(vars));
                    return null;
                }
                break;

            case UPDATE_NAMESPACE:
                if (asNamespaceCatalog != null) {
                    Namespace namespace = namespaceFromPathVars(vars);
                    UpdateNamespacePropertiesRequest request = castRequest(UpdateNamespacePropertiesRequest.class, body);
                    return castResponse(responseType, CatalogHandlers.updateNamespaceProperties(asNamespaceCatalog, namespace, request));
                }
                break;

            case LIST_TABLES: {
                Namespace namespace = namespaceFromPathVars(vars);
                return castResponse(responseType, CatalogHandlers.listTables(catalog, namespace));
            }

            case CREATE_TABLE: {
                Namespace namespace = namespaceFromPathVars(vars);
                CreateTableRequest request = castRequest(CreateTableRequest.class, body);
                request.validate();
                if (request.stageCreate()) {
                    return castResponse(responseType, CatalogHandlers.stageTableCreate(catalog, namespace, request));
                }
                else {
                    return castResponse(responseType, CatalogHandlers.createTable(catalog, namespace, request));
                }
            }

            case DROP_TABLE: {
                CatalogHandlers.dropTable(catalog, identFromPathVars(vars));
                return null;
            }

            case LOAD_TABLE: {
                TableIdentifier ident = identFromPathVars(vars);
                return castResponse(responseType, CatalogHandlers.loadTable(catalog, ident));
            }

            case UPDATE_TABLE: {
                TableIdentifier ident = identFromPathVars(vars);
                UpdateTableRequest request = castRequest(UpdateTableRequest.class, body);
                return castResponse(responseType, CatalogHandlers.updateTable(catalog, ident, request));
            }

            case RENAME_TABLE: {
                RenameTableRequest request = castRequest(RenameTableRequest.class, body);
                CatalogHandlers.renameTable(catalog, request);
                return null;
            }

            default:
        }

        return null;
    }

    public <T extends RESTResponse> T execute(HTTPMethod method, String path, Map<String, String> queryParams, Object body, Class<T> responseType, Map<String, String> headers, Consumer<ErrorResponse> errorHandler)
    {
        ErrorResponse.Builder errorBuilder = ErrorResponse.builder();
        Pair<Route, Map<String, String>> routeAndVars = Route.from(method, path);
        if (routeAndVars != null) {
            try {
                ImmutableMap.Builder<String, String> vars = ImmutableMap.builder();
                if (queryParams != null) {
                    vars.putAll(queryParams);
                }
                vars.putAll(routeAndVars.second());

                return handleRequest(routeAndVars.first(), vars.buildOrThrow(), body, responseType);
            }
            catch (RuntimeException e) {
                configureResponseFromException(e, errorBuilder);
            }
        }
        else {
            errorBuilder.responseCode(400).withType("BadRequestException").withMessage(format("No route for request: %s %s", method, path));
        }

        ErrorResponse error = errorBuilder.build();
        errorHandler.accept(error);

        // if the error handler doesn't throw an exception, throw a generic one
        throw new RESTException("Unhandled error: %s", error);
    }

    @Override
    public <T extends RESTResponse> T delete(String path, Class<T> responseType, Map<String, String> headers, Consumer<ErrorResponse> errorHandler)
    {
        return execute(HTTPMethod.DELETE, path, null, null, responseType, headers, errorHandler);
    }

    @Override
    public <T extends RESTResponse> T post(String path, RESTRequest body, Class<T> responseType, Map<String, String> headers, Consumer<ErrorResponse> errorHandler)
    {
        return execute(HTTPMethod.POST, path, null, body, responseType, headers, errorHandler);
    }

    @Override
    public <T extends RESTResponse> T get(String path, Map<String, String> queryParams, Class<T> responseType, Map<String, String> headers, Consumer<ErrorResponse> errorHandler)
    {
        return execute(HTTPMethod.GET, path, queryParams, null, responseType, headers, errorHandler);
    }

    @Override
    public void head(String path, Map<String, String> headers, Consumer<ErrorResponse> errorHandler)
    {
        execute(HTTPMethod.HEAD, path, null, null, null, headers, errorHandler);
    }

    @Override
    public <T extends RESTResponse> T postForm(String path, Map<String, String> formData, Class<T> responseType, Map<String, String> headers, Consumer<ErrorResponse> errorHandler)
    {
        return execute(HTTPMethod.POST, path, null, formData, responseType, headers, errorHandler);
    }

    @Override
    public void close()
            throws IOException
    {
        // The calling test is responsible for closing the underlying catalog backing this REST catalog
        // so that the underlying backend catalog is not closed and reopened during the REST catalog's
        // initialize method when fetching the server configuration.
    }

    public HttpServlet servlet()
    {
        return new AdaptorServlet();
    }

    enum HTTPMethod
    {
        GET, HEAD, POST, DELETE
    }

    private enum Route
    {
        TOKENS(HTTPMethod.POST, "v1/oauth/tokens", null, OAuthTokenResponse.class), CONFIG(HTTPMethod.GET, "v1/config", null, ConfigResponse.class), LIST_NAMESPACES(HTTPMethod.GET, "v1/namespaces", null, ListNamespacesResponse.class), CREATE_NAMESPACE(HTTPMethod.POST, "v1/namespaces", CreateNamespaceRequest.class, CreateNamespaceResponse.class), LOAD_NAMESPACE(HTTPMethod.GET, "v1/namespaces/{namespace}", null, GetNamespaceResponse.class), DROP_NAMESPACE(HTTPMethod.DELETE, "v1/namespaces/{namespace}"), UPDATE_NAMESPACE(HTTPMethod.POST, "v1/namespaces/{namespace}/properties", UpdateNamespacePropertiesRequest.class, UpdateNamespacePropertiesResponse.class), LIST_TABLES(HTTPMethod.GET, "v1/namespaces/{namespace}/tables", null, ListTablesResponse.class), CREATE_TABLE(HTTPMethod.POST, "v1/namespaces/{namespace}/tables", CreateTableRequest.class, LoadTableResponse.class), LOAD_TABLE(HTTPMethod.GET, "v1/namespaces/{namespace}/tables/{table}", null, LoadTableResponse.class), UPDATE_TABLE(HTTPMethod.POST, "v1/namespaces/{namespace}/tables/{table}", UpdateTableRequest.class, LoadTableResponse.class), DROP_TABLE(HTTPMethod.DELETE, "v1/namespaces/{namespace}/tables/{table}"), RENAME_TABLE(HTTPMethod.POST, "v1/tables/rename", RenameTableRequest.class, null);

        private final HTTPMethod method;
        private final int requriedLength;
        private final Map<Integer, String> requirements;
        private final Map<Integer, String> variables;
        private final Class<? extends RESTRequest> requestClass;
        private final Class<? extends RESTResponse> responseClass;

        Route(HTTPMethod method, String pattern)
        {
            this(method, pattern, null, null);
        }

        Route(HTTPMethod method, String pattern, Class<? extends RESTRequest> requestClass, Class<? extends RESTResponse> responseClass)
        {
            this.method = method;

            // parse the pattern into requirements and variables
            List<String> parts = SLASH.splitToList(pattern);
            ImmutableMap.Builder<Integer, String> requirementsBuilder = ImmutableMap.builder();
            ImmutableMap.Builder<Integer, String> variablesBuilder = ImmutableMap.builder();
            for (int pos = 0; pos < parts.size(); pos += 1) {
                String part = parts.get(pos);
                if (part.startsWith("{") && part.endsWith("}")) {
                    variablesBuilder.put(pos, part.substring(1, part.length() - 1));
                }
                else {
                    requirementsBuilder.put(pos, part);
                }
            }

            this.requestClass = requestClass;
            this.responseClass = responseClass;

            this.requriedLength = parts.size();
            this.requirements = requirementsBuilder.buildOrThrow();
            this.variables = variablesBuilder.buildOrThrow();
        }

        public static Pair<Route, Map<String, String>> from(HTTPMethod method, String path)
        {
            List<String> parts = SLASH.splitToList(path);
            for (Route candidate : Route.values()) {
                if (candidate.matches(method, parts)) {
                    return Pair.of(candidate, candidate.variables(parts));
                }
            }

            return null;
        }

        private boolean matches(HTTPMethod requestMethod, List<String> requestPath)
        {
            return method == requestMethod && requriedLength == requestPath.size() && requirements.entrySet().stream().allMatch(requirement -> requirement.getValue().equalsIgnoreCase(requestPath.get(requirement.getKey())));
        }

        private Map<String, String> variables(List<String> requestPath)
        {
            ImmutableMap.Builder<String, String> vars = ImmutableMap.builder();
            variables.forEach((key, value) -> vars.put(value, requestPath.get(key)));
            return vars.buildOrThrow();
        }

        public Class<? extends RESTRequest> getRequestClass()
        {
            return requestClass;
        }

        public Class<? extends RESTResponse> getResponseClass()
        {
            return responseClass;
        }
    }

    private static class BadResponseType
            extends RuntimeException
    {
        private BadResponseType(Class<?> responseType, Object response)
        {
            super(format("Invalid response object, not a %s: %s", responseType.getName(), response));
        }
    }

    private static class BadRequestType
            extends RuntimeException
    {
        private BadRequestType(Class<?> requestType, Object request)
        {
            super(format("Invalid request object, not a %s: %s", requestType.getName(), request));
        }
    }

    private static class ServletRequestContext
    {
        private HTTPMethod method;
        private Route route;
        private String path;
        private Map<String, String> headers;
        private Map<String, String> queryParams;
        private Object body;

        private ErrorResponse errorResponse;

        private ServletRequestContext(ErrorResponse errorResponse)
        {
            this.errorResponse = errorResponse;
        }

        private ServletRequestContext(HTTPMethod method, Route route, String path, Map<String, String> headers, Map<String, String> queryParams, Object body)
        {
            this.method = method;
            this.route = route;
            this.path = path;
            this.headers = headers;
            this.queryParams = queryParams;
            this.body = body;
        }

        static ServletRequestContext from(HttpServletRequest request)
                throws IOException
        {
            HTTPMethod method = HTTPMethod.valueOf(request.getMethod());
            String path = request.getRequestURI().substring(1);
            Pair<Route, Map<String, String>> routeContext = Route.from(method, path);

            if (routeContext == null) {
                return new ServletRequestContext(ErrorResponse.builder().responseCode(400).withType("BadRequestException").withMessage(format("No route for request: %s %s", method, path)).build());
            }

            Route route = routeContext.first();
            Object requestBody = null;
            if (route.getRequestClass() != null) {
                requestBody = RESTObjectMapper.mapper().readValue(request.getReader(), route.getRequestClass());
            }
            else if (route == Route.TOKENS) {
                try (Reader reader = new InputStreamReader(request.getInputStream())) {
                    Splitter.MapSplitter formSplitter = Splitter.on("&").withKeyValueSeparator("=");
                    requestBody = formSplitter.split(CharStreams.toString(reader)).entrySet().stream().collect(Collectors.toMap(e -> RESTUtil.decodeString(e.getKey()), e -> RESTUtil.decodeString(e.getValue())));
                }
            }

            Map<String, String> queryParams = request.getParameterMap().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue()[0]));
            Map<String, String> headers = Collections.list(request.getHeaderNames()).stream().collect(Collectors.toMap(Function.identity(), request::getHeader));

            return new ServletRequestContext(method, route, path, headers, queryParams, requestBody);
        }

        public HTTPMethod method()
        {
            return method;
        }

        public Route route()
        {
            return route;
        }

        public String path()
        {
            return path;
        }

        public Map<String, String> headers()
        {
            return headers;
        }

        public Map<String, String> queryParams()
        {
            return queryParams;
        }

        public Object body()
        {
            return body;
        }

        public Optional<ErrorResponse> error()
        {
            return Optional.ofNullable(errorResponse);
        }
    }

    public class AdaptorServlet
            extends HttpServlet
    {
        private final Map<String, String> responseHeaders = ImmutableMap.of(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            execute(ServletRequestContext.from(request), response);
        }

        @Override
        protected void doHead(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            execute(ServletRequestContext.from(request), response);
        }

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            execute(ServletRequestContext.from(request), response);
        }

        @Override
        protected void doDelete(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            execute(ServletRequestContext.from(request), response);
        }

        private void execute(ServletRequestContext context, HttpServletResponse response)
                throws IOException
        {
            response.setStatus(HttpServletResponse.SC_OK);
            responseHeaders.forEach(response::setHeader);

            if (context.error().isPresent()) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                RESTObjectMapper.mapper().writeValue(response.getWriter(), context.error().get());
                return;
            }

            try {
                Object responseBody = RESTCatalogAdapter.this.execute(context.method(), context.path(), context.queryParams(), context.body(), context.route().getResponseClass(), context.headers(), handle(response));

                if (responseBody != null) {
                    RESTObjectMapper.mapper().writeValue(response.getWriter(), responseBody);
                }
            }
            catch (RESTException e) {
                //System.out.println(e.getMessage());
            }
            catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

        private Consumer<ErrorResponse> handle(HttpServletResponse response)
        {
            return (errorResponse) -> {
                response.setStatus(errorResponse.code());
                try {
                    RESTObjectMapper.mapper().writeValue(response.getWriter(), errorResponse);
                }
                catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            };
        }
    }

    public static Catalog backendCatalog() throws IOException
    {
        String CATALOG_ENV_PREFIX = "CATALOG_";

        // Translate environment variable to catalog properties
        Map<String, String> catalogProperties = System.getenv().entrySet().stream()
                .filter(e -> e.getKey().startsWith(CATALOG_ENV_PREFIX))
                .collect(Collectors.toMap(
                        e -> e.getKey().replace(CATALOG_ENV_PREFIX, "")
                                .replaceAll("__", "-")
                                .replaceAll("_", ".")
                                .toLowerCase(Locale.ROOT),
                        Map.Entry::getValue,
                        (m1, m2) -> { throw new IllegalArgumentException("Duplicate key"); },
                        HashMap::new
                ));

        // Fallback to a JDBCCatalog impl if one is not set
        catalogProperties.putIfAbsent(CatalogProperties.CATALOG_IMPL, "org.apache.iceberg.jdbc.JdbcCatalog");
        catalogProperties.putIfAbsent(CatalogProperties.URI, "jdbc:sqlite:file:/tmp/iceberg_rest_mode=memory");

        // Configure a default location if one is not specified
        String warehouseLocation = catalogProperties.get(CatalogProperties.WAREHOUSE_LOCATION);

        if (warehouseLocation == null) {
            File tmp = java.nio.file.Files.createTempDirectory("iceberg_warehouse").toFile();
            tmp.deleteOnExit();
            warehouseLocation = tmp.toPath().resolve("iceberg_data").toFile().getAbsolutePath();
            catalogProperties.put(CatalogProperties.WAREHOUSE_LOCATION, warehouseLocation);

            LOG.info("No warehouse location set.  Defaulting to temp location: {}", warehouseLocation);
        }

        LOG.info("Creating catalog with properties: {}", catalogProperties);
        return CatalogUtil.buildIcebergCatalog("rest_backend", catalogProperties, new Configuration());
    }

    public static void main(String[] args)
            throws Exception
    {
        RESTCatalogAdapter adapter = new RESTCatalogAdapter(backendCatalog());
        System.out.println("ENV VARS = " + System.getenv());

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
        context.setContextPath("/");
        ServletHolder servletHolder = new ServletHolder(adapter.servlet());
        servletHolder.setInitParameter("javax.ws.rs.Application", "ServiceListPublic");
        context.addServlet(servletHolder, "/*");
        context.setVirtualHosts(null);
        context.setGzipHandler(new GzipHandler());

        Server httpServer = new Server(PropertyUtil.propertyAsInt(System.getenv(), "REST_PORT", 8181));
        httpServer.setHandler(context);

        httpServer.start();
        httpServer.join();
    }
}
