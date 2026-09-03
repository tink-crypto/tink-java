// Copyright 2017 Google LLC
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

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

/**
 * A factory that returns JCE engines, using pre-specified j.security.Providers.
 *
 * <p>This class contains a lot of static factories and static functions returning factories: these
 * allow customization and hide the typing complexity in this class. To use this class, import it,
 * and replace your <code>Cipher.getInstance(...)</code> with <code>
 * EngineFactory.CIPHER.getInstance(...)</code>.
 *
 * @since 1.0.0
 */
public final class EngineFactory<T_WRAPPER extends EngineWrapper<JcePrimitiveT>, JcePrimitiveT> {
  private final T_WRAPPER instanceBuilder;

  /**
   * Returns the list of preferred security providers based on the runtime environment and the
   * caller-specified preferred providers:
   *
   * <ul>
   *   <li>In FIPS mode: [GmsCore_OpenSSL, AndroidOpenSSL, Conscrypt] (mandatory, ignores
   *       preferredProviders).
   *   <li>On Android: [GmsCore_OpenSSL, AndroidOpenSSL] (preferred, ignores preferredProviders).
   *   <li>Default JVM: preferredProviders.
   * </ul>
   */
  private static List<Provider> getProviders(List<Provider> preferredProviders) {
    if (TinkFipsUtil.useOnlyFips()) {
      // In Fips mode we ignore preferred providers (we assume we know better).
      return toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt");
    }
    if (SubtleUtil.isAndroid()) {
      // On Android we also ignore preferred providers (probably due to legacy).
      return toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL");
    }
    return preferredProviders;
  }

  public static final EngineFactory<EngineWrapper.TCipher, Cipher> CIPHER =
      new EngineFactory<>(new EngineWrapper.TCipher());

  public static final EngineFactory<EngineWrapper.TMac, Mac> MAC =
      new EngineFactory<>(new EngineWrapper.TMac());

  public static final EngineFactory<EngineWrapper.TSignature, Signature> SIGNATURE =
      new EngineFactory<>(new EngineWrapper.TSignature());

  public static final EngineFactory<EngineWrapper.TMessageDigest, MessageDigest> MESSAGE_DIGEST =
      new EngineFactory<>(new EngineWrapper.TMessageDigest());

  public static final EngineFactory<EngineWrapper.TKeyAgreement, KeyAgreement> KEY_AGREEMENT =
      new EngineFactory<>(new EngineWrapper.TKeyAgreement());

  public static final EngineFactory<EngineWrapper.TKeyPairGenerator, KeyPairGenerator>
      KEY_PAIR_GENERATOR = new EngineFactory<>(new EngineWrapper.TKeyPairGenerator());

  public static final EngineFactory<EngineWrapper.TKeyFactory, KeyFactory> KEY_FACTORY =
      new EngineFactory<>(new EngineWrapper.TKeyFactory());

  /** Helper function to get a list of Providers from names. */
  public static List<Provider> toProviderList(String... providerNames) {
    List<Provider> providers = new ArrayList<>();
    for (String s : providerNames) {
      Provider p = Security.getProvider(s);
      if (p != null) {
        providers.add(p);
      }
    }
    return providers;
  }

  public EngineFactory(T_WRAPPER instanceBuilder) {
    this.instanceBuilder = instanceBuilder;
  }

  public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException {
    return getInstance(algorithm, Collections.emptyList());
  }

  JcePrimitiveT getInstance(String algorithm, List<Provider> preferredProviders)
      throws GeneralSecurityException {
    Exception cause = null;
    for (Provider provider : getProviders(preferredProviders)) {
      try {
        return this.instanceBuilder.getInstance(algorithm, provider);
      } catch (GeneralSecurityException e) {
        if (cause == null) {
          cause = e;
        }
      }
    }
    if (TinkFipsUtil.useOnlyFips()) {
      // In FIPS mode, we do not attempt without giving a provider since we want to be strict.
      throw new GeneralSecurityException("No good Provider found.", cause);
    }
    return this.instanceBuilder.getInstance(algorithm, null);
  }
}
