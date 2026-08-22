package io.github.xesam.linkseal;

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
      return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception error) {
      throw new IllegalArgumentException("Invalid public key PEM", error);
    }
  }

  public static PrivateKey parsePrivateKey(String pem) {
    try {
      byte[] der = parsePem(pem, "PRIVATE KEY");
      return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
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
      if (wrong.contains("RSA") && label.equals("PRIVATE KEY")) {
        hint = " — LinkSeal accepts only PKCS#8 " + label
            + "; convert with: openssl pkcs8 -topk8 -nocrypt -in <key> -out <key>.p8.pem";
      } else if (wrong.contains("RSA") && label.equals("PUBLIC KEY")) {
        hint = " — LinkSeal accepts only PKCS#8 " + label
            + " (SPKI); regenerate from the private key with: openssl rsa -in <private.p8.pem> -pubout -out <public.spki.pem>";
      } else {
        hint = " — LinkSeal accepts only PKCS#8 " + label + ".";
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
