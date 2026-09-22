package io.github.xesam.unilink.seal.model;

public enum MissingPolicy {
  ERROR("error"),
  IGNORE("ignore"),
  DEFAULT("default");

  private final String wireValue;

  MissingPolicy(String wireValue) {
    this.wireValue = wireValue;
  }

  public String wireValue() {
    return wireValue;
  }
}
