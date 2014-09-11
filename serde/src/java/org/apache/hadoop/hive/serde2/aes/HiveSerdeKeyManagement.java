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
package org.apache.hadoop.hive.serde2.aes;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProvider.KeyVersion;
import org.apache.hadoop.crypto.key.kms.KMSClientProvider;
import org.apache.hadoop.security.authorize.AuthorizationException;

public class HiveSerdeKeyManagement {
  public static final String HIVE_ENCRYPT_KEYNAMES = "hive.encrypt.keynames";
  public static final String HIVE_ENCRYPT_IV = "hive.encrypt.iv";
  public static final String KMS_URI = "hadoop.security.kms.uri";

  private static Log LOG = LogFactory.getLog(HiveSerdeKeyManagement.class);

  public static void setupTableForEncryption(Configuration conf, Map<String, String> tblProps)
      throws IOException {
    if(tblProps == null) {
      return;
    }

    String keyNames = tblProps.get(HIVE_ENCRYPT_KEYNAMES);
    if (keyNames == null || keyNames.isEmpty()) {
      return;
    }

    String kmsUri = conf.get(KMS_URI);
    if (kmsUri == null) {
      LOG.warn("Please set " + KMS_URI + " if you want to enable encryption");
      return;
    }

    // 1. create key using kms
    try {
      URL url = new URL(kmsUri);
      URI uri = createKMSUri(url);
      KMSClientProvider kp = new KMSClientProvider(uri, conf);
      for (String keyName : AESUtil.getKeys(keyNames)) {
        KeyVersion kv = kp.getCurrentKey(keyName);
        if (kv == null) {
          kv = kp.createKey(keyName, new KeyProvider.Options(conf));
        }
      }
    } catch (URISyntaxException e) {
      throw new IOException("Bad configuration of " + KMS_URI + " at " + kmsUri, e);
    } catch (AuthorizationException e) {
      throw new IOException("Current user has no permission to get/create key", e);
    } catch (NoSuchAlgorithmException e) {
      throw new IOException("No such algorithm when create key", e);
    }

    // 2. generate iv and set to table properties
    byte[] ivBytes = AESUtil.randomBytes(AESConstants.IV_LENGTH);
    tblProps.put(HIVE_ENCRYPT_IV, AESUtil.encodeBytes(ivBytes));
  }

  public static URI createKMSUri(URL kmsUrl) throws URISyntaxException {
    String str = kmsUrl.toString();
    str = str.replaceFirst("://", "@");
    return new URI("kms://" + str);
  }
}
