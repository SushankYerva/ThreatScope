# Contributing to ThreatScope

Thank you for considering contributing.  
This guide explains the standards and workflow used in this repository.

---

## 1. Environment Setup

```bash
git clone https://github.com/<your-username>/threatscope.git
cd threatscope
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run tests to confirm environment:

```bash
pytest -q
```

---

## 2. Branching Model

- `main` → always stable, deployable  
- `dev` → integration branch  
- Feature branches: `feature/<topic>`  
- Bug fixes: `fix/<issue>`  
- Documentation only: `docs/<section>`

Example:

```bash
git checkout -b feature/add-anomaly-detector
```

---

## 3. Commit Rules

Follow the **Conventional Commits** pattern:

```
feat: add new feature
fix: correct packet timestamp overflow
docs: update API usage in README
refactor: restructure feature extractor
test: add unit tests for AlertLogger
chore: update CI dependencies
```

Keep commits small and descriptive.

---

## 4. Code Style

- **Python version:** 3.11+  
- Use **PEP-8** and **type hints**.  
- Format code with `black` and check imports with `isort`.  
- Run `pytest` before committing.

Example:

```bash
black src tests
pytest
```

---

## 5. Adding New Modules

Each new component must include:
- Docstring with purpose and usage.
- Minimal test coverage under `tests/`.
- Example call or integration in README if relevant.

---

## 6. Submitting a Pull Request

1. Fork the repository.  
2. Push your branch.  
3. Open a Pull Request (PR) into `dev`.  
4. Describe:
   - What the change does.
   - Why it matters.
   - Any testing steps or limitations.

CI must pass before maintainers review.

---

## 7. Reporting Issues

Use [GitHub Issues](../../issues) for:
- Bugs
- Feature requests
- Documentation errors

Include:
- OS and Python version
- Steps to reproduce
- Logs or screenshots if relevant

---

## 8. Security Disclosure

If you find a security vulnerability, please **do not open a public issue**.  
Email the maintainer directly at `<your-email@example.com>` so the fix can be coordinated responsibly.

---

## 9. License

By contributing, you agree that your code will be released under the same [MIT License](LICENSE).

---

## 10. Attribution

Major components and dependencies:
- [Scapy](https://scapy.net/)
- [PyShark](https://github.com/KimiNewt/pyshark)
- [XGBoost](https://xgboost.ai)
- [FastAPI](https://fastapi.tiangolo.com)
- [scikit-learn](https://scikit-learn.org)

---

*End of CONTRIBUTING guide.*
