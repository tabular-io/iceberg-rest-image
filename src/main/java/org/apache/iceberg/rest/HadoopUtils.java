/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

import java.io.File;

import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class to work with Apache Hadoop MapRed classes.
 */
public final class HadoopUtils {
    private static final Logger LOG = LoggerFactory.getLogger(RESTCatalogServer.class);

    /**
     * Returns a new Hadoop Configuration object using the path to the hadoop configuration
     * This method is public because its being used in the RESTCatalogServer.
     */
    public static org.apache.hadoop.conf.Configuration getCoreSiteConfiguration() {
        Configuration retConf = new org.apache.hadoop.conf.Configuration();

        // We need to load both core-site.xml to determine the default fs path
        // Approach environment variables
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                    "Building possible paths to core-site.xml for hadoop configuration");
        }
        String[] possibleHadoopConfPaths = new String[3];
        possibleHadoopConfPaths[0] = System.getenv("HADOOP_CONF_DIR");

        if (System.getenv("HADOOP_HOME") != null) {
            possibleHadoopConfPaths[1] = System.getenv("HADOOP_HOME") + "/conf";
            possibleHadoopConfPaths[2] = System.getenv("HADOOP_HOME") + "/etc/hadoop"; // hadoop 2.2
        }

        for (String possibleHadoopConfPath : possibleHadoopConfPaths) {
            if (possibleHadoopConfPath != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(
                            "Found possibleHadoopConfPath entry: " + possibleHadoopConfPath);
                }
                if (new File(possibleHadoopConfPath).exists()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "possibleHadoopConfPath entry (" + possibleHadoopConfPath + ") exists.");
                    }
                    if (new File(possibleHadoopConfPath + "/core-site.xml").exists()) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                    "Core Site config (" + possibleHadoopConfPath + "/core-site.xml) exists.");
                        }
                        retConf.addResource(
                                new org.apache.hadoop.fs.Path(possibleHadoopConfPath + "/core-site.xml"));

                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                    "Adding " + possibleHadoopConfPath + "/core-site.xml to hadoop configuration");
                        }
                    }
                }
            }
        }
        return retConf;
    }

    /**
     * Private constructor to prevent instantiation.
     */
    private HadoopUtils() {
        throw new RuntimeException();
    }
}