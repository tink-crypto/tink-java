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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.subtle.Base64;
import java.io.BufferedReader;
import java.io.StringReader;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PemUtilTest {

  @Test
  public void parsePublicKey_shouldWork() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(ecPublicKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isInstanceOf(X509EncodedKeySpec.class);
    assertThat(keySpec.getEncoded())
        .isEqualTo(
            Base64.decode(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
                    + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ=="));
  }

  @Test
  public void parsePrivateKey_shouldWork() throws Exception {
    String ecPrivateKeyPem =
        "-----BEGIN PRIVATE KEY-----\n"
            + "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49\n"
            + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l\n"
            + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q==\n"
            + "-----END PRIVATE KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(ecPrivateKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isInstanceOf(PKCS8EncodedKeySpec.class);
    assertThat(keySpec.getEncoded())
        .isEqualTo(
            Base64.decode(
                "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49"
                    + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l"
                    + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q=="));
  }

  @Test
  public void parsePublicKey_withStuffBeforeMarker_works() throws Exception {
    String ecPublicKeyPem =
        "some stuff\nbefore\nmarker\n-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(ecPublicKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isInstanceOf(X509EncodedKeySpec.class);
    assertThat(keySpec.getEncoded())
        .isEqualTo(
            Base64.decode(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
                    + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ=="));
  }

  @Test
  public void parsePublicKey_withHeaders_shouldIgnoreHeaderAndReturnKey() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "attribute: value\n"
            + "attribute2: value2\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(ecPublicKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isInstanceOf(X509EncodedKeySpec.class);
    assertThat(keySpec.getEncoded())
        .isEqualTo(
            Base64.decode(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
                    + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ=="));
  }

  @Test
  public void parsePrivateKeyWithPrefix_shouldWork() throws Exception {
    String ecPrivateKeyPem =
        "-----BEGIN MY KEY TYPE PRIVATE KEY-----\n"
            + "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49\n"
            + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l\n"
            + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q==\n"
            + "-----END MY KEY TYPE PRIVATE KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(ecPrivateKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isInstanceOf(PKCS8EncodedKeySpec.class);
    assertThat(keySpec.getEncoded())
        .isEqualTo(
            Base64.decode(
                "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49"
                    + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l"
                    + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q=="));
  }

  // TODO(b/470859537): We should probably not allow this.
  @Test
  public void parseWithoutEndMarker_works() throws Exception {
    String ecPrivateKeyPem =
        "-----BEGIN PRIVATE KEY-----\n"
            + "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49\n"
            + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l\n"
            + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q==\n";
    BufferedReader reader = new BufferedReader(new StringReader(ecPrivateKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isInstanceOf(PKCS8EncodedKeySpec.class);
    assertThat(keySpec.getEncoded())
        .isEqualTo(
            Base64.decode(
                "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49"
                    + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l"
                    + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q=="));
  }

  @Test
  public void parsePublicKey_withIncorrectMarker_shouldReturnNull() throws Exception {
    // This uses four "-" instead of five, which is incorrect.
    String pemWithIncorrectMarker =
        "----BEGIN PUBLIC KEY----\n"
            + "some-header: some value\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "----END PUBLIC KEY----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pemWithIncorrectMarker));
    assertThat(PemUtil.parsePemToKeySpec(reader)).isNull();
  }

  @Test
  public void parseUnknownKey_shouldReturnNull() throws Exception {
    String unknownKeyPem = "-----BEGIN UNKNOWN KEY-----\nabcdef\n-----END UNKNOWN KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(unknownKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isNull();
  }

  @Test
  public void parseIncompleteHeader_shouldReturnNull() throws Exception {
    String unknownKeyPem = "-----BEGIN PUBLIC KEY";
    BufferedReader reader = new BufferedReader(new StringReader(unknownKeyPem));
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    assertThat(keySpec).isNull();
  }

  @Test
  public void emptyReader_shouldReturnNull() throws Exception {
    BufferedReader emptyReader = new BufferedReader(new StringReader(""));
    assertThat(PemUtil.parsePemToKeySpec(emptyReader)).isNull();
  }
}
