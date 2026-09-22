package io.github.xesam.unilink.seal;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PemKeys {
  private static final Pattern PEM_LABEL = Pattern.compile("-----BEGIN ([A-Z ]+)-----");

  private PemKeys() {}

  public static PublicKey parsePublicKey(String pem) {
    try {
      byte[] der = parsePem(pem, "PUBLIC KEY");
      return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception error) {
      throw new IllegalArgumentException("Invalid public key PEM", error);
    }
  }

  public static PrivateKey parsePrivateKey(String pem) {
    try {
      byte[] der = parsePem(pem, "PRIVATE KEY");
      return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception error) {
      throw new IllegalArgumentException("Invalid private key PEM", error);
    }
  }

  private static byte[] parsePem(String pem, String label) {
    String begin = "-----BEGIN " + label + "-----";
    if (!pem.contains(begin)) {
      Matcher m = PEM_LABEL.matcher(pem);
      String wrong = m.find() ? m.group(1) : "(none)";
      String hint;
      if (wrong.contains("RSA")) {
        hint = " — LinkSeal uses Ed25519; generate one with: "
            + (label.equals("PRIVATE KEY")
                ? "openssl genpkey -algorithm Ed25519 -out <key>.pem"
                : "openssl pkey -in <private.pem> -pubout -out <public.spki.pem>");
      } else {
        hint = " — LinkSeal accepts only PKCS#8 " + label + " (Ed25519).";
      }
      throw new IllegalArgumentException(
          "Unsupported PEM label '-----BEGIN " + wrong + "-----'" + hint);
    }
    String body = pem
        .replace("-----BEGIN " + label + "-----", "")
        .replace("-----END " + label + "-----", "")
        .replaceAll("\\s", "");
    return Base64.getDecoder().decode(body);
  }
}
