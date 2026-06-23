# Law Navi

An interactive, plain-English map of United States law — federal, all 50 states, local, territories, tribal, "outside the states," procedure, the live battlegrounds, the schools of interpretation, and the documented ways the system gets gamed — plus a **Theory Builder** for constructing and stress-testing legal theories with import/export to interoperable standards (Akoma Ntoso, LegalRuleML, AIF, CSL-JSON, IRAC).

**Live:** https://pq-cybarg.github.io/lawnavi/

> ⚠️ **Educational information only — not legal advice.** The author is **not a lawyer**. This is general legal information published for public education; it is not the practice of law and creates no attorney-client relationship. It may be incomplete, out of date, or wrong, and portions were generated with AI. **Verify everything against primary sources and consult a licensed attorney** for any actual legal matter. See the in-app disclaimer for the full terms.

## What's here

| File | What it is |
|------|------------|
| `index.html` | The whole app — one self-contained file, works offline (no build step). |
| `sidecar/index.html` | Docs for the optional local privacy sidecar. |
| `lawnavi-local.mjs` | Optional Node service: PQC crypto + encrypted matter vault, **localhost-only**. |
| `package.json` | Dependencies for the sidecar (`@noble/hashes`, `@noble/post-quantum`). |

## Privacy

The app runs **entirely in your browser**. Theories are stored locally (optionally encrypted with AES-256-GCM via WebCrypto). The optional AI features talk **only to a local model endpoint you configure** (Ollama / llama.cpp / LM Studio) — never a cloud. The optional sidecar (`lawnavi-local.mjs`) binds to `127.0.0.1` only and keeps all data on your machine. See the [sidecar docs](sidecar/) for the cryptographic suite (argon2id · AES-256-GCM · KMAC256 · SHA3-256 · ML-DSA-87 · ML-KEM-1024) and FIPS notes.

## Run the sidecar (optional)

```bash
npm install
LAWNAVI_PASSPHRASE='a long passphrase you remember' node lawnavi-local.mjs
```

Then in the app: **🔒 → Detect local FIPS/PQC sidecar**.

## License

[MIT](LICENSE) — provided **"AS IS", without warranty of any kind**.
