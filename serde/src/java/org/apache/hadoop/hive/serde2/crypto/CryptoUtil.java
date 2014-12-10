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

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;

public class CryptoUtil {

  /**
   * Generate a number of secure, random bytes suitable for cryptographic use.
   *
   * @param conf
   * @param length
   */
  public static byte[] randomBytes(Configuration conf, int length) {
    final String secureRandomAlg = conf.get(
        CommonConfigurationKeysPublic.HADOOP_SECURITY_JAVA_SECURE_RANDOM_ALGORITHM_KEY,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_JAVA_SECURE_RANDOM_ALGORITHM_DEFAULT);
    SecureRandom random;
    try {
      random = SecureRandom.getInstance(secureRandomAlg);
    } catch (GeneralSecurityException e) {
      random = new SecureRandom();
    }
    byte[] result = new byte[length / 8];
    random.nextBytes(result);
    return result;
  }

  /**
   * Wrap data through Base64
   *
   * @param bytes
   * @return wrapped string of given bytes
   */
  public static String encodeBytes(byte[] bytes) throws UnsupportedEncodingException {
    return bytes == null ? null : new String(Base64.encodeBase64(bytes), Charset.forName("UTF-8"));
  }

  /**
   * Unwrap data through Base64
   *
   * @param str
   * @return unwrapped bytes of given string
   */
  public static byte[] decodeBytes(String str) throws UnsupportedEncodingException {
    return Base64.decodeBase64(str.getBytes(Charset.forName("UTF-8")));
  }

  /**
   * Copy <code>len-pos</code> bytes start from b[pos]
   *
   * @param b
   * @param pos
   * @param len
   */
  public static byte[] copyBytes(byte[] b, int pos, int len) {
    return Arrays.copyOfRange(b, pos, len);
  }

}
