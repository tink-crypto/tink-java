// Copyright 2023 Google LLC
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

package com.google.crypto.tink.prf.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.HmacPrfParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSet;
import com.google.crypto.tink.prf.internal.LegacyHmacPrfTestUtil.HmacLegacyPrfTestVector;
import com.google.crypto.tink.proto.HmacPrfParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Verifies that LegacyFullPrf is correctly integrated with the Tink ecosystem. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class LegacyFullPrfIntegrationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacPrfKey";
  private static final EnumTypeProtoConverter<
          com.google.crypto.tink.proto.HashType, HmacPrfParameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter
              .<com.google.crypto.tink.proto.HashType, HmacPrfParameters.HashType>builder()
              .add(com.google.crypto.tink.proto.HashType.SHA1, HmacPrfParameters.HashType.SHA1)
              .add(com.google.crypto.tink.proto.HashType.SHA224, HmacPrfParameters.HashType.SHA224)
              .add(com.google.crypto.tink.proto.HashType.SHA256, HmacPrfParameters.HashType.SHA256)
              .add(com.google.crypto.tink.proto.HashType.SHA384, HmacPrfParameters.HashType.SHA384)
              .add(com.google.crypto.tink.proto.HashType.SHA512, HmacPrfParameters.HashType.SHA512)
              .build();

  @DataPoints("hmacPrfTestVectors")
  public static final HmacLegacyPrfTestVector[] HMAC_LEGACY_PRF_TEST_VECTORS =
      LegacyHmacPrfTestUtil.HMAC_LEGACY_PRF_TEST_VECTORS;

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyHmacPrfTestKeyManager.register();
  }

  @Theory
  public void endToEnd_works(@FromDataPoints("hmacPrfTestVectors") HmacLegacyPrfTestVector t)
      throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(LegacyFullPrf::create, LegacyProtoKey.class, Prf.class));
    TestLegacyPrfWrapper.register();

    KeysetHandle keysetHandle = getKeysetHandleFromKeyNoSerialization(t.key);
    PrfSet prfSet = keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    Prf prf = prfSet.getPrfs().get(prfSet.getPrimaryId());

    assertThat(prf).isInstanceOf(LegacyFullPrf.class);
    assertThat(prf.compute(t.message, t.tag.length)).isEqualTo(t.tag);
  }

  /* This test verifies that when a wrapper is not registered, primitive creation fails.

    Ideally we should also verify that when the KeyManager for such a primitive is not registered,
    the object creation fails. However, with the current Registry API this is not possible.
    Concretely, once a KeyManager is registered, there is no way to deregister it from the
    Registry (resetting PrimitiveRegistry does not affect this). In the case of these tests, the
    KeyManager is registered for the endToEnd_works() test, so we would need to do either of the
    three things:
        1. make the reset() method public in Registry
        2. move the test into a separate file
        3. add a method to deregister KeyManagers from Registry
    #1 and #3 we really don't want in order not to tempt users to use it, #2 is a bit
    overcomplicated and is not worth it. */
  @Test
  public void legacyFullPrfNotRegistered_fails() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();

    KeysetHandle keysetHandle =
        getKeysetHandleFromKeyNoSerialization(HMAC_LEGACY_PRF_TEST_VECTORS[0].key);

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class));
  }

  private static KeysetHandle getKeysetHandleFromKeyNoSerialization(HmacPrfKey key)
      throws GeneralSecurityException {
    KeyData rawKeyData =
        KeyData.newBuilder()
            .setValue(
                com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                    .setParams(
                        HmacPrfParams.newBuilder()
                            .setHash(
                                HASH_TYPE_CONVERTER.toProtoEnum(key.getParameters().getHashType()))
                            .build())
                    .setKeyValue(
                        ByteString.copyFrom(
                            key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())))
                    .build()
                    .toByteString())
            .setTypeUrl(TYPE_URL)
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .build();
    int id = key.getIdRequirementOrNull() == null ? 42 : key.getIdRequirementOrNull();
    Keyset.Key rawKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(rawKeyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(id)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    return TinkProtoKeysetFormat.parseKeyset(
        Keyset.newBuilder().addKey(rawKeysetKey).setPrimaryKeyId(id).build().toByteArray(),
        InsecureSecretKeyAccess.get());
  }

  private static final class TestLegacyPrfWrapper implements PrimitiveWrapper<Prf, PrfSet> {
    static final TestLegacyPrfWrapper WRAPPER = new TestLegacyPrfWrapper();

    @Immutable
    private static final class WrappedPrfSet extends PrfSet {

      private final Integer primaryKeyId;
      @SuppressWarnings("Immutable")
      private final Map<Integer, Prf> keyIdToPrfMap;

      @Override
      public int getPrimaryId() {
        return primaryKeyId;
      }

      @Override
      public Map<Integer, Prf> getPrfs() throws GeneralSecurityException {
        return keyIdToPrfMap;
      }

      private WrappedPrfSet(KeysetHandleInterface keysetHandle, PrimitiveFactory<Prf> factory)
          throws GeneralSecurityException {
        KeysetHandleInterface.Entry primary = keysetHandle.getPrimary();
        this.primaryKeyId = primary.getId();
        HashMap<Integer, Prf> keyIdToPrfMap = new HashMap<>();
        keyIdToPrfMap.put(this.primaryKeyId, factory.create(primary));
        this.keyIdToPrfMap = Collections.unmodifiableMap(keyIdToPrfMap);
      }
    }

    @Override
    public PrfSet legacyWrap(
        KeysetHandleInterface keysetHandle,
        MonitoringAnnotations annotations,
        PrimitiveFactory<Prf> factory)
        throws GeneralSecurityException {
      // This is a dummy test wrapper that act as a proxy to a single primitive object under test.
      return new WrappedPrfSet(keysetHandle, factory);
    }

    @Override
    public Class<PrfSet> getPrimitiveClass() {
      return PrfSet.class;
    }

    @Override
    public Class<Prf> getInputPrimitiveClass() {
      return Prf.class;
    }

    static void register() throws GeneralSecurityException {
      MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    }
  }
}
