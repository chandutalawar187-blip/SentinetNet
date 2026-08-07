# Contributing to SentinetNet

Thank you for your interest in contributing to **SentinetNet** — a lightweight ML-powered network intrusion detection toolkit. We welcome contributions of all kinds!

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Contribution Rules](#contribution-rules)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## 🤝 Code of Conduct

By participating in this project, you agree to uphold a respectful and inclusive environment. We do not tolerate harassment, discrimination, or abusive behavior of any kind toward contributors or maintainers.

---

## 🚀 Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/SentinetNet.git
   cd SentinetNet
   ```
3. **Set up** your development environment:
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # macOS/Linux
   source .venv/bin/activate

   pip install -r requirements.txt
   ```
4. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## 🛠 How to Contribute

### Types of Contributions We Welcome
- 🐛 Bug fixes
- ✨ New features (detection algorithms, dashboard improvements, etc.)
- 📝 Documentation improvements
- 🧪 New tests and test improvements
- 🔧 Performance improvements
- 🌐 Cross-platform compatibility fixes

---

## 📏 Contribution Rules

These rules **must** be followed for your PR to be considered:

### 1. One Change Per Pull Request
Keep each PR focused on a **single feature or fix**. Do not bundle unrelated changes.

### 2. Tests Are Required
- All new features **must** include corresponding tests in the `tests/` directory.
- All bug fixes **must** include a regression test that would have caught the bug.
- Tests must pass before a PR is submitted.

### 3. No Breaking Changes Without Discussion
- If your change breaks existing APIs or behavior, open an **issue first** to discuss it.
- Breaking changes require maintainer approval before a PR is submitted.

### 4. Do Not Commit Secrets or Credentials
- **Never** commit API keys, tokens, passwords, or private data.
- Use environment variables or `.env` files (which are gitignored) for secrets.
- If you accidentally commit a secret, notify the maintainers immediately.

### 5. Security-Related Contributions
- Any changes to `blocker.py`, packet capture logic, or privilege-requiring code must be reviewed carefully.
- Explain the security implications in your PR description.

### 6. Keep Dependencies Minimal
- Do not add heavy new dependencies without a strong justification.
- Prefer using the Python standard library and existing project dependencies.

### 7. Do Not Commit Trained Models Without Permission
- Large `.pkl` or model files should not be committed without prior discussion.
- Use the `data/` and `models/` directories only as outlined in the README.

### 8. No AI-Generated Code Without Review
- If you use AI tools to assist in writing code, you are responsible for reviewing, understanding, and testing every line before submitting.

---

## 🔄 Pull Request Process

1. Ensure all tests pass locally:
   ```bash
   python -m pytest tests/ -v
   ```
2. Update `README.md` if your change affects usage or setup.
3. Fill out the PR template completely.
4. Link any related issues in the PR description using `Closes #<issue-number>`.
5. A maintainer will review your PR within **5 business days**.
6. Address all review comments before the PR can be merged.
7. Squash commits before final merge if requested.

---

## 💻 Coding Standards

### Python
- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines.
- Use type hints where applicable.
- Maximum line length: **100 characters**.
- Use descriptive variable and function names.
- Add docstrings to all public functions and classes.

```python
# Good
def detect_intrusion(flow_data: dict, threshold: float = 0.85) -> bool:
    """
    Detect whether a network flow is malicious.

    Args:
        flow_data: Dictionary of flow features.
        threshold: Confidence threshold for classification.

    Returns:
        True if the flow is classified as an intrusion.
    """
    ...

# Bad
def detect(d, t=0.85):
    ...
```

### Node.js / JavaScript
- Use `const` and `let`, never `var`.
- Follow the existing code style in `lib/`.
- Async operations should use Promises or `async/await`.

---

## 📝 Commit Message Guidelines

Use the **Conventional Commits** format:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types:**
| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or fixing tests |
| `refactor` | Code change that isn't a fix or feature |
| `perf` | Performance improvement |
| `chore` | Build process or tooling changes |

**Examples:**
```
feat(detector): add LSTM-based anomaly detection model
fix(capture): handle scapy timeout on empty interfaces
docs(readme): add Docker setup instructions
test(model): add edge case tests for zero-flow input
```

---

## 🐛 Reporting Bugs

Please open an issue with the following information:
- **OS and Python version**
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Relevant logs or error messages**

---

## 💡 Feature Requests

Open an issue with the `enhancement` label and describe:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

---

## 🔒 Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Please report them privately to the maintainers by emailing the repository owner directly or using GitHub's private security advisory feature.

---

## 🙏 Thank You

Every contribution, big or small, makes SentinetNet better. We appreciate your time and effort!
