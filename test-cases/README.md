# Security scanner test cases

[vulnerable-webapp](vulnerable-webapp/README.md) is a deliberately vulnerable,
standalone Python web application covering XSS, CSRF, clickjacking, SQL injection,
hardcoded credentials, and sensitive HTML comments. All records and credentials
are synthetic. Run it on localhost for manual or automated testing.

These fixtures are source-review targets, not part of the BonnyAI service. The
production Docker build copies only the main `app/` directory and its entry point;
it does not include or run `test-cases/`.
