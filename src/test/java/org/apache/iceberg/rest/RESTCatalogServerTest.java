package org.apache.iceberg.rest;

import org.junit.jupiter.api.Test;

import static org.apache.iceberg.rest.RESTCatalogServer.envKeyToPropertyKey;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RESTCatalogServerTest {

  @Test
  void shouldConvertEnvironmentVariablesCorrectly() {
    assertEquals("test-double-underscore", envKeyToPropertyKey("CATALOG_TEST__DOUBLE__UNDERSCORE", "CATALOG_"));
    assertEquals("test-single.underscore", envKeyToPropertyKey("CATALOG_TEST__SINGLE_UNDERSCORE", "CATALOG_"));
    assertEquals("test-upperCase", envKeyToPropertyKey("CATALOG_TEST__UPPER_U_CASE", "CATALOG_"));
    assertEquals("test-upperCase.with.dots-and-upperCaseWords-in.one", envKeyToPropertyKey("CATALOG_TEST__UPPER_U_CASE_WITH_DOTS__AND__UPPER_U_CASE_U_WORDS__IN_ONE", "CATALOG_"));
  }
}