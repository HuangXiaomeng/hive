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
package org.apache.hadoop.hive.common.crypto;

import org.junit.Assert;
import org.junit.Test;

public class TestCipherSuite {
  @Test
  public void testAesCtr() throws Exception {
    CipherSuite SUITE = CipherSuite.AES_CTR_NOPADDING;
    Assert.assertEquals("AES/CTR/NoPadding", SUITE.getName());
    Assert.assertEquals(16, SUITE.getBlockSize());

    String trueAlgoName = "AES/CTR/NoPadding";
    String wrongAlogName = "AES/CTR/NoPadding/Wrong";
    CipherSuite.checkName(trueAlgoName);
    try {
      CipherSuite.checkName(wrongAlogName);
      Assert.fail("wrong cipher algorithm");
    } catch (Exception e) {
      // no-op
    }

    SUITE = CipherSuite.convert(trueAlgoName);
    Assert.assertEquals("AES/CTR/NoPadding", SUITE.getName());
    Assert.assertEquals(16, SUITE.getBlockSize());

    try {
      SUITE = CipherSuite.convert(wrongAlogName);
      Assert.fail("wrong cipher algorithm");
    } catch (Exception e) {
      // no-op
    }
  }
}
