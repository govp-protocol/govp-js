# Contributing

Contributions that improve interoperability, portability, documentation and
adversarial coverage are welcome.

Before opening a pull request:

1. install with `npm ci`;
2. run `npm test`, `npm audit --audit-level=low` and `npm pack --dry-run`;
3. preserve every existing conformance verdict;
4. add a regression test for behavioral changes;
5. explain any effect on browser and supported Node.js runtimes.

GOVP-1 is frozen. Do not resolve specification ambiguity by choosing new
behavior inside this implementation. Open an issue in the canonical
[`govp`](https://github.com/govp-protocol/govp) repository first.

Never include private keys, customer data, production records or non-public
product material. Report vulnerabilities through [SECURITY.md](SECURITY.md).
