// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;

import java.security.Provider;
import java.security.Security;
import java.util.List;
import javax.crypto.Cipher;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for EngineFactory. */
@RunWith(JUnit4.class)
public class EngineFactoryTest {

  static Provider conscrypt;

  @BeforeClass
  public static void setUp() throws Exception {
    if (!SubtleUtil.isAndroid() && Conscrypt.isAvailable()) {
      conscrypt = Conscrypt.newProvider();
      Security.addProvider(conscrypt);
    }
  }

  @Test
  public void testAtLeastGetsACipherByDefault() throws Exception {
    Object unused = EngineFactory.CIPHER.getInstance("AES");
    // didn't throw
  }

  @Test
  public void testIsReuseable() throws Exception {
    Object unused = EngineFactory.CIPHER.getInstance("AES");
    unused = EngineFactory.CIPHER.getInstance("AES");
    unused = EngineFactory.CIPHER.getInstance("AES");
    // didn't throw
  }

  @Test
  public void testDefaultPolicyStillPrefersDefaultProviders() throws Exception {
    Assume.assumeFalse(SubtleUtil.isAndroid());
    Assume.assumeTrue(Conscrypt.isAvailable());

    String conscryptName = conscrypt.getName();

    // We expect that JDK gets picked first nonetheless.
    assertThat(EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding").getProvider().getName())
        .isNotEqualTo(conscryptName);
  }

  @Test
  public void testDefaultPolicyRespectsPreferredProviders() throws Exception {
    Assume.assumeFalse(SubtleUtil.isAndroid());
    Assume.assumeTrue(Conscrypt.isAvailable());

    String conscryptName = conscrypt.getName();
    List<Provider> preferredProviders = EngineFactory.toProviderList(conscryptName);

    // Check if Conscrypt can provide this cipher.
    assertThat(Cipher.getInstance("AES/GCM/NoPadding", conscrypt)).isNotNull();

    // We expect that our preferred provider is picked.
    assertThat(
            EngineFactory.CIPHER
                .getInstance("AES/GCM/NoPadding", preferredProviders)
                .getProvider()
                .getName())
        .isEqualTo(conscryptName);
  }

  @Test
  public void testAndroidPolicyUsesConscrypt() throws Exception {
    Assume.assumeTrue(SubtleUtil.isAndroid());

    // We expect that the Android policy will prefer Conscrypt if available is on that Android
    // device.
    if (Security.getProvider("GmsCore_OpenSSL") != null) {
      assertThat(EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding").getProvider().getName())
          .isEqualTo("GmsCore_OpenSSL");

    } else if (Security.getProvider("AndroidOpenSSL") != null) {
      assertThat(EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding").getProvider().getName())
          .isEqualTo("AndroidOpenSSL");
    }
  }

  @Test
  public void testAndroidPolicyAlwaysPrefersConscrypt() throws Exception {
    Assume.assumeTrue(SubtleUtil.isAndroid());

    List<Provider> preferredProviders = EngineFactory.toProviderList("BC", "Crypto");

    // We expect that the Android policy will prefer Conscrypt if available is on that Android
    // device.
    if (Security.getProvider("GmsCore_OpenSSL") != null) {
      assertThat(
              EngineFactory.CIPHER
                  .getInstance("AES/GCM/NoPadding", preferredProviders)
                  .getProvider()
                  .getName())
          .isEqualTo("GmsCore_OpenSSL");

    } else if (Security.getProvider("AndroidOpenSSL") != null) {
      assertThat(
              EngineFactory.CIPHER
                  .getInstance("AES/GCM/NoPadding", preferredProviders)
                  .getProvider()
                  .getName())
          .isEqualTo("AndroidOpenSSL");
    }
  }
}
