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

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Properties;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.CryptoCodec;
import org.apache.hadoop.crypto.CryptoInputStream;
import org.apache.hadoop.crypto.CryptoOutputStream;
import org.apache.hadoop.crypto.key.KeyProvider.KeyVersion;
import org.apache.hadoop.hive.serde2.AbstractFieldRewriter;
import org.apache.hadoop.hive.serde2.ByteStream;
import org.apache.hadoop.hive.serde2.typeinfo.TypeInfo;
import org.apache.hadoop.io.DataInputBuffer;
import org.apache.hadoop.io.DataOutputBuffer;

public class CryptoRewriter extends AbstractFieldRewriter {
  private CryptoCodec codec;
  private byte[] keyBytes;
  private byte[] ivBytes;
  private boolean isEncode = true;
  private static final int bufferSize = 4096;
  private static Log LOG = LogFactory.getLog(CryptoRewriter.class);

  @Override
  public void init(List<String> columnNames, List<TypeInfo> columnTypes, Properties properties,
      Configuration conf) throws IOException {
    String keyNames = properties.getProperty(CryptoConstants.HIVE_ENCRYPT_KEYNAMES);

    if (keyNames == null || keyNames.isEmpty()) {
      isEncode = false;
      LOG.warn("Please set " + CryptoConstants.HIVE_ENCRYPT_KEYNAMES);
      return;
    }

    String kmsUri = conf.get(CryptoConstants.KMS_URI);
    if (kmsUri == null) {
      isEncode = false;
      LOG.warn("Please set " + CryptoConstants.KMS_URI);
      return;
    }

    try {
      // currently just support all columns share one key
      KeyVersion kv = HiveSerdeKeyManagement.getFirstKey(conf, kmsUri, keyNames);
      codec = CryptoCodec.getInstance(conf);
      keyBytes = kv.getMaterial();
      ivBytes = CryptoUtil.decodeBytes(properties.getProperty(CryptoConstants.HIVE_ENCRYPT_IV));
    } catch (IOException e) {
      // if current user has no permission to access this key
      // we will don't do encrypt/decrypt
      isEncode = false;
    }
  }

  @Override
  public void encode(int index, ByteStream.Input input, ByteStream.Output output)
      throws IOException {
    if (!isEncode) {
      output.write(input.toBytes());
      return;
    }

    byte[] data = input.toBytes();
    int dataLen = data.length;

    // 1. Encrypt data
    DataOutputBuffer encryptedDataBuffer = new DataOutputBuffer();
    CryptoOutputStream out = new CryptoOutputStream(encryptedDataBuffer,
        codec, bufferSize, keyBytes, ivBytes);
    out.write(data, 0, dataLen);
    out.flush();
    out.close();

    // 2. Wrap data through Base64
    byte[] encryptedData = CryptoUtil.copyBytes(encryptedDataBuffer.getData(),
        0, encryptedDataBuffer.getLength());
    byte[] wrappedBytes = Base64.encodeBase64(encryptedData);

    // 3. Write to output
    // Encrypted block format:
    // +--------------------------+
    // | byte original length     |
    // +--------------------------+
    // | encrypted block data ... |
    // +--------------------------+
    output.write(dataLen);
    output.write(wrappedBytes);
    LOG.info("Finished encrypting data");
  }

  @Override
  public void decode(int index, ByteStream.Input input, ByteStream.Output output)
      throws IOException {
    if (!isEncode) {
      output.write(input.toBytes());
      return;
    }

    // 1.1 first read length of origin data
    int dataLen = input.read();
    // 1.2 read remaining data bytes
    byte[] wrappedBytes = input.toBytes();
    // 1.3 Unwrap data through Base64
    byte[] unwrappedBytes = Base64.decodeBase64(wrappedBytes);

    // 2. Decrypt data
    DataInputBuffer decryptedDataBuffer = new DataInputBuffer();
    decryptedDataBuffer.reset(unwrappedBytes, 0, unwrappedBytes.length);
    CryptoInputStream in = new CryptoInputStream(decryptedDataBuffer,
        codec, bufferSize, keyBytes, ivBytes);
    DataInputStream dataIn = new DataInputStream(new BufferedInputStream(in));
    byte[] decryptedData = new byte[dataLen];
    dataIn.readFully(decryptedData);
    dataIn.close();

    // 3. Write to output
    output.write(decryptedData);
    LOG.info("Finished decrypting data");
  }
}
