// Copyright 2026 Google LLC
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

package com.google.crypto.tink.jwt.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtMlDsaPublicKey;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtMlDsaProtoSerializationTest {
  private static final MlDsaPrivateKey MLDSA_44_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_44,
                      MlDsaParameters.Variant.NO_PREFIX))
              .getPrivateKey();

  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    ProtoParametersSerialization serialization =
        JwtMlDsaProtoSerialization.serializeParameters(parameters);
    Parameters parsed = JwtMlDsaProtoSerialization.parseParameters(serialization);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyBase64_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);

    ProtoParametersSerialization serialization =
        JwtMlDsaProtoSerialization.serializeParameters(parameters);
    Parameters parsed = JwtMlDsaProtoSerialization.parseParameters(serialization);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParameters_customKid_fails() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaProtoSerialization.serializeParameters(parameters));
  }

  @Test
  public void serializeParsePublicKey_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPublicKey publicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(MLDSA_44_KEY.getPublicKey().getSerializedPublicKey())
            .build();

    ProtoKeySerialization serialization =
        JwtMlDsaProtoSerialization.serializePublicKey(publicKey, /* access= */ null);
    JwtMlDsaPublicKey parsed =
        JwtMlDsaProtoSerialization.parsePublicKey(serialization, /* access= */ null);

    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Test
  public void serializeParsePrivateKey_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPublicKey publicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(MLDSA_44_KEY.getPublicKey().getSerializedPublicKey())
            .build();
    JwtMlDsaPrivateKey privateKey =
        JwtMlDsaPrivateKey.create(publicKey, MLDSA_44_KEY.getPrivateSeed());

    ProtoKeySerialization serialization =
        JwtMlDsaProtoSerialization.serializePrivateKey(privateKey, InsecureSecretKeyAccess.get());
    JwtMlDsaPrivateKey parsed =
        JwtMlDsaProtoSerialization.parsePrivateKey(serialization, InsecureSecretKeyAccess.get());

    assertThat(parsed.equalsKey(privateKey)).isTrue();
  }
}
