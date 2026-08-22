import { describe, it, expect } from 'vitest';
import { ProtocolSigner } from '../ProtocolSigner.js';
import type { LinkSealProtocol } from 'linkseal';

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDV5CJ2ronxFM4k
j1YaIjI32lxMR6Kc2J7wA5iMJ6kYzsAOeiechLATUz8z4uO0HOlCHWecGr3PHVWE
wAaG9k6cJtjnQWONiZjtppGPy54Sf3WF40+dnJKu2fIcoJohAHTM8Z8/sHesWeuf
0VON8EsyBYHV9alZlrz0QXKJgEyGL+O/FGXojcengPYSbcbKSSykXc0etzQKxrOq
zpSjyICl1yjpW7lrY9GGSSoRqLJmNjWrbgRZeXjjKCnIHk4js6q49Kv17By13j3d
287quPlxx/M5DVCTQ0fmh765Bih7Snj0H2XKZKR8RwXsn95LgWIPXPto8p9lpwPN
D2UfWPd7AgMBAAECggEAUGpKmMNLQlPXowAu13l21u/mVplyJjT9IHDBqCP7G8QT
if3cKajrSAC62OebQ2rBOeWzQAn/xcAaGGRXr+Mnr+adEujPJHYQhHzk6iKcJgk8
pp9NHg0xSsLPF3s8J180Cp9nB3txqt9NypLZLpqissZGR6pqRq/5D34RsWeGncXw
cOie07R06pu/UmKEN/r1YpW842evpxAu5gU0LyUV5tZ2yInqVrBapbbJonfp3uTJ
9bjXfz1Y0xLMOcS1Yb1EAsPgih9tyCZt66RL5vc5E8EWjoPXnkASkwbD3KXM8mMq
5v3LZ4lBfl8nyF+LmdI57/KdWImuBNg2V0q7CT/DcQKBgQDypauvX+9Y4F2m2tF/
7377kbZ4RAORBwEw5PP6QV/L8D2zcQ7te00Jf2s9pOCQCFn20O0Zon3vBde+Fwii
7kDBc7AJx09wwfaRaqlPQ8afZ38ySYKN2uP2Cwg3hMK6Q++tvjkcEwjaCgJ2bAXg
xb94BPIT4Sgva+sR8j95xRp/CwKBgQDhqVv/pg40hX+frLSWf3N4IN7u0HuH+P5p
PN5GE+k+OtcEbbtB3c5cXeXc6Qcnxsu+KO7mtr7HN5xd/fhSOHMzFF1Hu8YM1ka1
Zmu0XLcecG9pM/cas0OGC2Gd9B1txHvN76w3Es7fk/M3kAbpi1QGChmkf7kJ/8n9
ZymPL0NvUQKBgD3wLkAJFBayxxUlfB7VKqvaySIv8l0d1Z7+gozaDTMIsydP78iN
FeAbx2sn4C7EAvru3+cQRGc0LZsXVBwLBzqaZlBIsS2ORXtfJ7LVESl1iNF0VEAT
pOcUb9eEKxTS7KaEDR3uee72aSSDdIio0bQ4RvbuHYzlVk7xcGSL/LR7AoGBALn6
VjPvqy1mCLSUJZETIRsUHCc981EwyJv66kVfC4+Z9rNTrEywfO5rBJJ4CsmhcTEb
kyjZ24lcL6bXNNyuYWLrmaURADx8LHI8Iu/WqaSQjYFqrnB25WOH5b/D/K0GjfI/
YPNSsORajsxwCwJXLbx8fn2wNdQj11jcuMek8DLBAoGBAOjSBNrXe6UyuMgFYAVX
JeZe5xgWRoMw1DwbZFO+stPBqsWtt27vzUwUNWNi29E+2VvSn7WZcj7nZyOrZjcy
wapN86thTBZnuH4AUqKpElFGRLbQ/ZZK67XXKaYOtCkVR8yPlEG0cQnPlB8+Dd10
+RIYiFCRI/fj/RcOg2F0v0ks
-----END PRIVATE KEY-----`;

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1eQidq6J8RTOJI9WGiIy
N9pcTEeinNie8AOYjCepGM7ADnonnISwE1M/M+LjtBzpQh1nnBq9zx1VhMAGhvZO
nCbY50FjjYmY7aaRj8ueEn91heNPnZySrtnyHKCaIQB0zPGfP7B3rFnrn9FTjfBL
MgWB1fWpWZa89EFyiYBMhi/jvxRl6I3Hp4D2Em3GykkspF3NHrc0Csazqs6Uo8iA
pdco6Vu5a2PRhkkqEaiyZjY1q24EWXl44ygpyB5OI7OquPSr9ewctd493dvO6rj5
ccfzOQ1Qk0NH5oe+uQYoe0p49B9lymSkfEcF7J/eS4FiD1z7aPKfZacDzQ9lH1j3
ewIDAQAB
-----END PUBLIC KEY-----`;

function makePayload(): LinkSealProtocol {
  return {
    version: '1.0',
    template: 'https://api.example.com/users/{userId}{?token}',
    policy: { missing: 'error' },
  };
}

describe('ProtocolSigner', () => {
  it('throws when signing without setting a private key', async () => {
    const signer = new ProtocolSigner();
    await expect(signer.signPayload(makePayload())).rejects.toThrow('Private key not set');
  });

  it('produces a base64 signature', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);
    const signature = await signer.signPayload(makePayload());
    expect(signature).toBeTruthy();
    expect(typeof signature).toBe('string');
    // Should be valid base64
    expect(() => atob(signature)).not.toThrow();
  });

  it('signProtocol returns payload with signature', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);
    const signed = await signer.signProtocol(makePayload());
    expect(signed.payload).toEqual(makePayload());
    expect(signed.signature).toBeTruthy();
  });

  it('produces deterministic signatures for the same payload', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);
    const sig1 = await signer.signPayload(makePayload());
    const sig2 = await signer.signPayload(makePayload());
    expect(sig1).toBe(sig2);
  });

  it('throws on invalid PEM key', async () => {
    const signer = new ProtocolSigner();
    await expect(signer.setPrivateKey('not-a-valid-key')).rejects.toThrow();
  });

  it('signs different payloads differently', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const a = makePayload();
    const b = { ...makePayload(), template: 'https://other.com/{id}' };
    const sigA = await signer.signPayload(a);
    const sigB = await signer.signPayload(b);
    expect(sigA).not.toBe(sigB);
  });

  // Regression: canonicalization once ignored nested keys, so payloads
  // differing only inside policy shared a signature.
  it('signs payloads differing only in policy differently', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const base = await signer.signPayload(makePayload());
    const downgraded = await signer.signPayload({
      ...makePayload(),
      policy: { missing: 'ignore' },
    });
    expect(base).not.toBe(downgraded);
  });

  it('signs payloads differing only in policy defaults differently', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const a = await signer.signPayload({
      ...makePayload(),
      policy: { missing: 'default', defaults: { userId: 'anon' } },
    });
    const b = await signer.signPayload({
      ...makePayload(),
      policy: { missing: 'default', defaults: { userId: 'admin' } },
    });
    expect(a).not.toBe(b);
  });

  it('is insensitive to key insertion order', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const base = await signer.signPayload(makePayload());
    const reordered = await signer.signPayload({
      policy: { missing: 'error' },
      template: 'https://api.example.com/users/{userId}{?token}',
      version: '1.0',
    });
    expect(base).toBe(reordered);
  });
});
