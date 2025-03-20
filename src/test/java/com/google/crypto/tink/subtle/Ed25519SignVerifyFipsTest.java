// Copyright 2025 Google LLC
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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Ed25519SignVerifyFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  // Test case from https://www.rfc-editor.org/rfc/rfc8032#page-24
  private static final SecretBytes SECRET_KEY_BYTES =
      SecretBytes.copyFrom(
          Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
          InsecureSecretKeyAccess.get());
  private static final Bytes PUBLIC_KEY_BYTES =
      Bytes.copyFrom(
          Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));

  @Test
  public void ed25519SignCreate_throws() throws Exception {
    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, SECRET_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () -> {
          PublicKeySign unused = Ed25519Sign.create(privateKey);
        });
  }

  @Test
  public void ed25519VerifyCreate_throws() throws Exception {
    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);
    assertThrows(
        GeneralSecurityException.class,
        () -> {
          PublicKeyVerify unused = Ed25519Verify.create(publicKey);
        });
  }

  @Test
  public void ed25519SignConstructor_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> {
          Ed25519Sign unused =
              new Ed25519Sign(SECRET_KEY_BYTES.toByteArray(InsecureSecretKeyAccess.get()));
        });
  }

  @Test
  public void ed25519VerifyConstructor_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> {
          Ed25519Verify unused = new Ed25519Verify(PUBLIC_KEY_BYTES.toByteArray());
        });
  }
}
