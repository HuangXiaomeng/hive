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

package org.apache.hadoop.hive.common.crypto;

import org.apache.hadoop.classification.InterfaceAudience;

/**
 * CipherSuite includes cipher name and block size.
 */
@InterfaceAudience.Private
public enum CipherSuite {
  UNKNOWN("Unknown", 0),
  AES_CTR_NOPADDING("AES/CTR/NoPadding", 16),
  AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding", 16);

  private final String name;
  private final int blockSize;

  CipherSuite(String name, int blockSize) {
    this.name = name;
    this.blockSize = blockSize;
  }

  /**
   * Return name(i.e. algorithm/mode/padding) of cipher suite
   */
  public String getName() {
    return name;
  }

  /**
   * Return the block size of an algorithm
   */
  public int getBlockSize() {
    return blockSize;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder("{");
    builder.append("name: " + name);
    builder.append(", algorithmBlockSize: " + blockSize);
    builder.append("}");
    return builder.toString();
  }

  /**
   * Check if the cipher name match anyone from CipherSuite
   * @param name cipher suite name
   */
  public static void checkName(String name) {
    CipherSuite[] suites = CipherSuite.values();
    for (CipherSuite suite : suites) {
      if (suite.getName().equals(name)) {
        return;
      }
    }
    throw new IllegalArgumentException("Invalid cipher suite name: " + name);
  }

  /**
   * Convert to CipherSuite from a cipher name.
   * @param name cipher suite name
   * @return CipherSuite cipher suite
   */
  public static CipherSuite convert(String name) {
    CipherSuite[] suites = CipherSuite.values();
    for (CipherSuite suite : suites) {
      if (suite.getName().equals(name)) {
        return suite;
      }
    }
    throw new IllegalArgumentException("Invalid cipher suite name: " + name);
  }
}
