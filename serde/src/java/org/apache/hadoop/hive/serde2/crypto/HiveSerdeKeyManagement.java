/**
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
package org.apache.hadoop.hive.serde2.crypto;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProvider.KeyVersion;
import org.apache.hadoop.crypto.key.KeyProviderFactory;
import org.apache.hadoop.security.authorize.AuthorizationException;

public class HiveSerdeKeyManagement {
  private static Log LOG = LogFactory.getLog(HiveSerdeKeyManagement.class);

  /**
   * Setup table if set properties of encryption
   *
   * @param conf
   * @param tblProps
   */
  public static void setupTableForEncryption(Configuration conf, Map<String, String> tblProps)
      throws IOException {
    if(tblProps == null) {
      return;
    }

    String keyNames = tblProps.get(CryptoConstants.HIVE_ENCRYPT_KEYNAMES);
    if (keyNames == null || keyNames.isEmpty()) {
      return;
    }

    String kmsUri = conf.get(CryptoConstants.KMS_URI);
    if (kmsUri == null) {
      LOG.warn("Please set " + CryptoConstants.KMS_URI + " if you want to enable encryption");
      return;
    }

    // 1. create keys using kms
    createKeys(conf, kmsUri, keyNames);

    // 2. generate iv and set to table properties
    byte[] ivBytes = CryptoUtil.randomBytes(conf, CryptoConstants.IV_LENGTH);
    tblProps.put(CryptoConstants.HIVE_ENCRYPT_IV, CryptoUtil.encodeBytes(ivBytes));
  }

  /**
   * Create keys through given key names from kms server
   *
   * @param conf
   * @param kmsUri
   * @param keyNames
   */
  public static void createKeys(Configuration conf, String kmsUri, String keyNames)
      throws IOException {
    try {
      KeyProvider kp = getKeyProvider(conf, kmsUri);
      for (String keyName : getKeyNames(keyNames)) {
        KeyVersion kv = kp.getCurrentKey(keyName);
        if (kv == null) {
          kv = kp.createKey(keyName, new KeyProvider.Options(conf));
        }
      }
    } catch (AuthorizationException e) {
      throw new IOException("Current user has no permission to get/create key", e);
    } catch (NoSuchAlgorithmException e) {
      throw new IOException("No such algorithm when create key", e);
    }
  }

  /**
   * Get first key through given key names from kms server
   *
   * @param conf
   * @param kmsUri
   * @param keyNames
   */
  public static KeyVersion getFirstKey(Configuration conf, String kmsUri, String keyNames)
      throws IOException {
    KeyProvider kp = getKeyProvider(conf, kmsUri);
    String keyName = getKeyNames(keyNames).get(0);
    KeyVersion kv = kp.getCurrentKey(keyName);
    if (kv == null) {
      throw new IOException("Can't get the key when do ser/deser");
    }
    return kv;
  }

  /**
   * Get a list of keys through given key names from kms server
   *
   * @param conf
   * @param kmsUri
   * @param keyNames
   */
  public static List<KeyVersion> getKeys(Configuration conf, String kmsUri, String keyNames)
      throws IOException {
    List<KeyVersion> kvs = new ArrayList<KeyVersion>();
    KeyProvider kp = getKeyProvider(conf, kmsUri);
    for (String keyName : getKeyNames(keyNames)) {
      kvs.add(kp.getCurrentKey(keyName));
    }
    return kvs;
  }

  private static KeyProvider getKeyProvider(Configuration conf, String kmsUri)
      throws IOException {
    try {
      URI uri = new URI(kmsUri);
      return KeyProviderFactory.get(uri, conf);
    } catch (URISyntaxException e) {
      throw new IOException("Bad configuration of " + KeyProviderFactory.KEY_PROVIDER_PATH +
          " at " + kmsUri, e);
    }
  }

  private static List<String> getKeyNames(String keyNames) {
    List<String> keys = new ArrayList<String>();
    for (String key : keyNames.split(",")) {
      keys.add(key.trim());
    }
    return keys;
  }
}
