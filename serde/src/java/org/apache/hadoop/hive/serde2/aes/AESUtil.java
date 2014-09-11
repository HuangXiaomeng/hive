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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESUtil {
  /**
   * Generate 256bit key/iv for AES-256 or 128bit key/iv for AES-128 from a string
   *
   * @param password
   * @param cryptographicLength
   * @return the key/iv byte array which is the length according to cryptographicLength
   * @throws CryptoException
   */
  public static byte[] hash(String password, int cryptographicLength) throws CryptoException {
    try {
      if(cryptographicLength == 256)
        return sha256(password.getBytes("UTF-8"));
      else
        return sha1(password.getBytes("UTF-8"));
    } catch (UnsupportedEncodingException ex) {
      throw new CryptoException(ex);
    }
  }

  public static byte[] sha1(byte[] input) throws CryptoException {
    try {
      MessageDigest sha;
      sha = MessageDigest.getInstance("SHA-1");
      sha.update(input);
      byte[] result = sha.digest();
      return Arrays.copyOf(result, 16);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException("Cannot generate native password from input key", e);
    }
  }

  public static byte[] sha256(byte[] input) throws CryptoException {
    try {
      final byte[] result = new byte[32];
      MessageDigest sha256;
      sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(input);
      sha256.digest(result, 0, result.length);
      return result;
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException("Cannot generate native password from input key", e);
    } catch (DigestException e) {
      throw new CryptoException("Cannot generate native password from input key", e);
    }
  }

  // length in bits
  public static byte[] randomBytes(int length) {
    Random rand = new Random();
    byte[] result = new byte[length / 8];
    rand.nextBytes(result);
    return result;
  }

  public static byte[] randomBytes(byte[] key) {
    Random rand = new Random();
    rand.nextBytes(key);
    return key;
  }

  public static SecretKey convert2SecretKey(byte[] key) {
    return new SecretKeySpec(key, "AES");
  }

  public static IvParameterSpec convert2IvSpec(byte[] iv) {
    return new IvParameterSpec(iv);
  }

  public static String encodeBytes(byte[] bytes) throws UnsupportedEncodingException {
    return bytes == null ? null : new String(Base64.encodeBase64(bytes), Charset.forName("UTF-8"));
  }

  public static byte[] decodeBytes(String str) throws UnsupportedEncodingException {
    return Base64.decodeBase64(str.getBytes(Charset.forName("UTF-8")));
  }

  // support every column has a key in future
  public static List<String> getKeys(String keyNames) {
    List<String> keys = new ArrayList<String>();
    for (String key : keyNames.split(",")) {
      keys.add(key.trim());
    }
    return keys;
  }
}
