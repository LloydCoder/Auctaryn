# Contributing to Auctaryn

Contributions should improve correctness, security, maintainability, or developer experience without weakening the project's trust boundaries.

## Development setup

Use Python 3.11 or 3.12 and Node.js 22 for dashboard work, matching CI.

```bash
git clone https://github.com/LloydCoder/Auctaryn.git
cd Auctaryn
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
```

For dashboard changes, run `npm ci` and `npm run build` from `dashboard/`.

## Workflow

1. Fork the repository or create a focused feature branch if you have write access.
2. Make one coherent change and add regression tests for behavior changes.
3. Update documentation, configuration examples, and changelog when relevant.
4. Run applicable tests and checks; report exact commands and actual results.
5. Push the branch and open a pull request against `main`.
6. Respond to review feedback and ensure required CI passes.

## Checks

```bash
python -m pytest tests/ -v --cov=core --cov=api --cov=modules --cov-report=term-missing
ruff check --select E4,E7,E9,F core/ api/ modules/
bash -n scripts/deploy.sh
bash -n scripts/rollback.sh
```

For dashboard changes, run `npm ci` and `npm run build` inside `dashboard/`. CI also performs dependency, container, CodeQL, secret-scanning, and supply-chain checks. Do not claim a check passed unless it actually ran successfully.

## Security and architecture

- Tinlance Agent Platform remains authoritative for identity, tenant binding, policy, approvals, governed execution, secrets, and audit.
- Auctaryn risk assessments are advisory; they do not grant permission or execute tools.
- TADL remains the developer-facing layer; Agent OS owns workspace, lifecycle, fleet, and user-facing operations above the Platform.
- Treat submitted context and caller-supplied metadata as untrusted. Do not claim runtime observation without evidence from a trusted integration.
- Never commit secrets, tokens, private keys, customer data, or unredacted logs.
- Keep dependencies pinned, tests meaningful, and operational changes documented with rollback guidance.

Use clear imperative commit messages. Conventional Commit prefixes are welcome but not mandatory. The repository uses a single-maintainer model; changes to authorization, execution, evidence integrity, runtime isolation, or secret handling require particularly careful review.

By contributing, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). The project is licensed under Apache-2.0; only submit material you are authorized to contribute.
