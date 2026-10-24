# iOS Security Analysis via GitHub Actions

Бесплатный полноценный анализ iOS приложений через GitHub Actions macOS runner.

## Как использовать

1. Создать публичный GitHub репозиторий
2. Скопировать содержимое этой папки в репозиторий
3. Скопировать папку `scripts/frida-ios/` из `/systems/soft/iphone/scripts/frida-ios/`
4. Сделать push — workflow запустится автоматически
5. Результаты — во вкладке Actions → Artifacts

Для анализа другого IPA: Actions → Run workflow → вставить URL IPA.

## Что анализирует

- **Static (Ubuntu):** MobSF — ATS, binary findings, hardcoded secrets, URLs, permissions
- **Dynamic (macOS):** Frida — network hooks, keychain dump, NSUserDefaults, objection
- **Code (Ubuntu):** Semgrep — Swift/ObjC правила OWASP
