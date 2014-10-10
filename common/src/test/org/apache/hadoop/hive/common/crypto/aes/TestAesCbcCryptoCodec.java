/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hive.common.crypto.aes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.common.crypto.CipherSuite;
import org.apache.hadoop.hive.common.crypto.CryptoCodec;
import org.apache.hadoop.hive.common.crypto.CryptoCodecFactory;
import org.apache.hadoop.hive.common.crypto.Decryptor;
import org.apache.hadoop.hive.common.crypto.Encryptor;
import org.apache.hadoop.hive.common.crypto.Key;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TestAesCbcCryptoCodec {
  private SecureRandom rng;
  private Key key;
  private final byte[] iv = new byte[16];

  @Before
  public void setUp() throws Exception{
    rng = SecureRandom.getInstance("SHA1PRNG");
    byte[] keyBytes = new byte[16];
    rng.nextBytes(keyBytes);
    key = new Key("key1", keyBytes);
    rng.nextBytes(iv);
  }

  @Test
  public void testBasic() throws Exception {
    Configuration conf = new Configuration();
    conf.set("hive.security.crypto.codec", JceAesCbcCryptoCodec.class.getName());
    conf.set("hive.security.crypto.cipher.suite", "AES/CBC/PKCS5Padding");
    CryptoCodec codec = CryptoCodecFactory.getInstance(conf);
    Assert.assertEquals(CipherSuite.AES_CBC_PKCS5PADDING, codec.getCipherSuite());
    Assert.assertEquals("AES", codec.getAlgorithm());
    Assert.assertEquals(JceAesCtrCryptoCodec.KEY_LENGTH, codec.getKeyLength());
    Assert.assertEquals(JceAesCtrCryptoCodec.IV_LENGTH, codec.getIvLength());
  }

  @Test
  public void testEncrypt() throws Exception {
    Configuration conf = new Configuration();
    conf.set("hive.security.crypto.codec", JceAesCbcCryptoCodec.class.getName());
    conf.set("hive.security.crypto.cipher.suite", "AES/CBC/PKCS5Padding");
    CryptoCodec codec = CryptoCodecFactory.getInstance(conf);

    Encryptor encryptor = codec.createEncryptor();
    encryptor.setKey(key);
    encryptor.setIv(iv);
    String text = "TestAesCbcCryptoCodec#testEncrypt";
    ByteArrayInputStream in = new ByteArrayInputStream(text.getBytes());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    encryptor.encrypt(in, out);
    byte[] encryptedText = out.toByteArray();
    Assert.assertNotSame(text, new String(encryptedText));

    Decryptor decryptor = codec.createDecryptor();
    decryptor.setKey(key);
    decryptor.setIv(iv);
    in = new ByteArrayInputStream(encryptedText);
    out = new ByteArrayOutputStream();
    decryptor.decrypt(in, out, text.getBytes().length);
    String decryptedText = new String(out.toByteArray());
    Assert.assertEquals(text, decryptedText);
  }
}
