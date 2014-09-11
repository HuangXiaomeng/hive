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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider.KeyVersion;
import org.apache.hadoop.crypto.key.kms.KMSClientProvider;
import org.apache.hadoop.hive.serde2.AbstractFieldRewriter;
import org.apache.hadoop.hive.serde2.ByteStream;
import org.apache.hadoop.hive.serde2.typeinfo.TypeInfo;
import org.apache.hadoop.security.authorize.AuthorizationException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;

public class AESRewriter extends AbstractFieldRewriter {
  private Cipher cipher;
  private byte[] keyBytes;
  private byte[] ivBytes;
  private boolean isEncode = true;
  private static Log LOG = LogFactory.getLog(AESRewriter.class);

  @Override
  public void init(List<String> columnNames, List<TypeInfo> columnTypes, Properties properties,
      Configuration conf) throws IOException {
    String keyNames = properties.getProperty(HiveSerdeKeyManagement.HIVE_ENCRYPT_KEYNAMES);

    if (keyNames == null || keyNames.isEmpty()) {
      isEncode = false;
      LOG.warn("Please set " + HiveSerdeKeyManagement.HIVE_ENCRYPT_KEYNAMES);
      return;
    }

    String kmsUri = conf.get(HiveSerdeKeyManagement.KMS_URI);
    if (kmsUri == null) {
      isEncode = false;
      LOG.warn("Please set " + HiveSerdeKeyManagement.KMS_URI);
      return;
    }

    KeyVersion kv = null;
    try {
      URL url = new URL(kmsUri);
      URI uri = HiveSerdeKeyManagement.createKMSUri(url);
      KMSClientProvider kp = new KMSClientProvider(uri, conf);
      // now just support all columns share one key
      String keyName = AESUtil.getKeys(keyNames).get(0);
      kv = kp.getCurrentKey(keyName);
      if (kv == null) {
        throw new IOException("Cant get the key when do ser/deser");
      }
    } catch (URISyntaxException e) {
      throw new IOException("Bad configuration of " + HiveSerdeKeyManagement.KMS_URI +
          " at " + kmsUri, e);
    } catch (AuthorizationException e) {
      isEncode = false;
      return;
    }

    try {
      cipher = CipherFactory.getInstance(AESConstants.ALGORITHM, AESConstants.PROVIDER);
    } catch (Exception e) {
      throw new IOException("Failed to initiate cipher object.", e);
    }

    keyBytes = kv.getMaterial();
    ivBytes = AESUtil.decodeBytes(properties.getProperty(HiveSerdeKeyManagement.HIVE_ENCRYPT_IV));
  }

  @Override
  public void encode(int index, ByteStream.Input input, ByteStream.Output output)
      throws IOException {
    try {
      if (!isEncode) {
        output.write(input.toBytes());
        return;
      }
      cipher.init(Cipher.ENCRYPT_MODE, AESUtil.convert2SecretKey(keyBytes),
          AESUtil.convert2IvSpec(ivBytes));
      byte[] encryptedBytes = cipher.doFinal(input.toBytes());
      byte[] wrappedBytes = Base64.encodeBase64(encryptedBytes);
      output.write(wrappedBytes);
    } catch (Exception e) {
      throw new IOException(e.getMessage());
    }
  }

  @Override
  public void decode(int index, ByteStream.Input input, ByteStream.Output output)
      throws IOException {
    try {
      if (!isEncode) {
        output.write(input.toBytes());
        return;
      }
      cipher.init(Cipher.DECRYPT_MODE, AESUtil.convert2SecretKey(keyBytes),
          AESUtil.convert2IvSpec(ivBytes));
      byte[] unwrappedBytes = Base64.decodeBase64(input.toBytes());
      byte[] plaintextBytes = cipher.doFinal(unwrappedBytes);
      output.write(plaintextBytes);
    } catch (Exception e) {
      throw new IOException(e.getMessage());
    }
  }
}
