# CLI exit codes

| Code | Meaning |
| --- | --- |
| 0 | Help/version, successful inspection (including explicit empty auth), or unchanged diff |
| 1 | Valid diff with changed authorization scope |
| 2 | Invalid flags/arguments, unreadable input, malformed JSON or invalid XDR |
| 3 | Failed simulation, missing auth array or unsupported/incomplete simulation shape |

`authscope inspect simulation.json --json` and `authscope diff before.json after.json --json` print JSON to stdout for valid inputs. Errors print sanitized classifications only to stderr, with no source paths, raw XDR, credentials or stack traces. `authscope --help` and `authscope --version` exit zero. An explicitly present empty `auth: []` is a successful *observation of no authorization entries*, not a security assessment. A missing authorization array or RPC simulation error is never treated as clean.
