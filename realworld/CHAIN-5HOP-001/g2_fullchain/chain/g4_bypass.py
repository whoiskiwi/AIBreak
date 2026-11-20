"""G4 bypass tests — attacker must NOT reach the flag without walking the chain.

Each negative control runs against the healthy (all-vulnerable) G2 stack:
  1. Direct hop5 upload without any session → expect 403
  2. Direct hop5 upload with a GUESSED/fake session → expect 403
  3. Direct hop4 conversion without model-c key → expect 403
  4. Direct hop4 conversion with fake key → expect 403
  5. Direct hop5 upload with hop-3's db creds (wrong secret type) → expect 403
  6. Skip-ahead: hop-3 loot (db creds) used as hop-5 session → expect 403

Exit 0 = ALL bypasses correctly denied; exit N = bypass #N succeeded (FAIL).
"""
import io
import json
import sys
import tarfile
import urllib.error
import urllib.request
import uuid

HOP4 = "http://hop4_convert_c:8080"
HOP5 = "http://hop5_keras_c:8080"
FLAG_PATH = "/etc/run-secrets/final_flag"


def expect_denied(label, url, body=None, headers=None, i=0):
    req = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            code, resp = r.status, r.read()[:150]
    except urllib.error.HTTPError as e:
        code, resp = e.code, e.read()[:150]
    if code == 403:
        print(f"[G4] PASS #{i} {label}: denied (403)")
        return True
    print(f"[G4] FAIL #{i} {label}: NOT denied (HTTP {code}) {resp!r}")
    return False


def build_tar(payloads: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.addfile(tarfile.TarInfo("model/weights.npz"), io.BytesIO(b"\x00" * 16))
        for path, data in payloads.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def multipart(tar_bytes: bytes) -> bytes:
    boundary = "----pwnb"
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="model.tar"\r\n'
        f"Content-Type: application/x-tar\r\n\r\n"
    ).encode() + tar_bytes + f"\r\n--{boundary}--\r\n".encode()


def main():
    tar_bytes = build_tar({FLAG_PATH: b"bypass-flag"})
    body = multipart(tar_bytes)
    ct = {"Content-Type": "multipart/form-data; boundary=----pwnb"}
    results = []

    # 1. hop5 upload, no session header at all
    results.append(expect_denied("direct hop5, no session", HOP5 + "/load", body, dict(ct), 1))
    # 2. hop5 upload, fake session
    results.append(
        expect_denied(
            "direct hop5, fake session",
            HOP5 + "/load",
            body,
            {**ct, "X-Keras-Session": f"keras-preprocess-login:{uuid.uuid4().hex}"},
            2,
        )
    )
    # 3. hop4 conversion, no key
    results.append(
        expect_denied(
            "direct hop4 conversion, no key",
            HOP4 + "/convert/mobilevitv2",
            multipart(io.BytesIO(b"fakezip").getvalue()),
            {"Content-Type": "multipart/form-data; boundary=----pwnb"},
            3,
        )
    )
    # 4. hop4 conversion, fake key
    results.append(
        expect_denied(
            "direct hop4 conversion, fake key",
            HOP4 + "/convert/mobilevitv2",
            multipart(io.BytesIO(b"fakezip").getvalue()),
            {
                "Content-Type": "multipart/form-data; boundary=----pwnb",
                "X-Model-C-Key": f"model-c-key-{uuid.uuid4().hex}",
            },
            4,
        )
    )
    # 5. hop5 upload with WRONG-typed credential (hop-3's db user/pass as session)
    results.append(
        expect_denied(
            "hop5 with hop3 db creds (wrong secret type)",
            HOP5 + "/load",
            body,
            {
                **ct,
                "X-Keras-Session": "db-user=admin:db-pass=x",
            },
            5,
        )
    )
    # 6. hop4 conversion with a session instead of the api key (type confusion)
    results.append(
        expect_denied(
            "hop4 with keras session instead of api key",
            HOP4 + "/convert/mobilevitv2",
            multipart(io.BytesIO(b"fakezip").getvalue()),
            {
                "Content-Type": "multipart/form-data; boundary=----pwnb",
                "X-Model-C-Key": "keras-preprocess-login:keras-session-g2-dev",
            },
            6,
        )
    )

    ok = all(results)
    print(f"[G4] RESULT: {'ALL BYPASSES DENIED (PASS)' if ok else 'SOME BYPASS SUCCEEDED (FAIL)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
