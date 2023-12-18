package org.apache.iceberg.rest;

import org.apache.iceberg.aws.s3.S3FileIOProperties;
import org.apache.iceberg.azure.AzureProperties;
import org.apache.iceberg.catalog.Catalog;
import org.apache.iceberg.gcp.GCPProperties;
import org.apache.iceberg.rest.RESTCatalogServer.CatalogContext;
import org.apache.iceberg.rest.responses.LoadTableResponse;
import org.apache.iceberg.util.PropertyUtil;

import java.util.Map;

public class RESTServerCatalogAdapter extends RESTCatalogAdapter {
    private static final String INCLUDE_CREDENTIALS = "include-credentials";

    private final CatalogContext catalogContext;


    public RESTServerCatalogAdapter(CatalogContext catalogContext) {
        super(catalogContext.catalog());

        this.catalogContext = catalogContext;
    }

    @Override
    public <T extends RESTResponse> T handleRequest(Route route, Map<String, String> vars, Object body, Class<T> responseType) {
        T restResponse = super.handleRequest(route, vars, body, responseType);

        if (restResponse instanceof LoadTableResponse loadTableResponse) {
            if (PropertyUtil.propertyAsBoolean(catalogContext.configuration(), INCLUDE_CREDENTIALS, false)) {
                applyCredentials(catalogContext.configuration(), loadTableResponse.config());
            }
        }

        return restResponse;
    }

    private void applyCredentials(Map<String, String> catalogConfig, Map<String, String> tableConfig) {
        if (catalogConfig.containsKey(S3FileIOProperties.ACCESS_KEY_ID)) {
            tableConfig.put(S3FileIOProperties.ACCESS_KEY_ID, catalogConfig.get(S3FileIOProperties.ACCESS_KEY_ID));
        }

        if (catalogConfig.containsKey(S3FileIOProperties.SECRET_ACCESS_KEY)) {
            tableConfig.put(S3FileIOProperties.SECRET_ACCESS_KEY, catalogConfig.get(S3FileIOProperties.SECRET_ACCESS_KEY));
        }

        if (catalogConfig.containsKey(S3FileIOProperties.SESSION_TOKEN)) {
            tableConfig.put(S3FileIOProperties.SESSION_TOKEN, catalogConfig.get(S3FileIOProperties.SESSION_TOKEN));
        }

        if (catalogConfig.containsKey(GCPProperties.GCS_OAUTH2_TOKEN)) {
            tableConfig.put(GCPProperties.GCS_OAUTH2_TOKEN, catalogConfig.get(GCPProperties.GCS_OAUTH2_TOKEN));
        }

        Map<String, String> azureTokens = PropertyUtil.propertiesWithPrefix(catalogConfig, AzureProperties.ADLS_SAS_TOKEN_PREFIX);
        if (!azureTokens.isEmpty()) {
            tableConfig.putAll(azureTokens);
        }
    }
}
