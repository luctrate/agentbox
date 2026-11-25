# Repository workflow

- Run tests locally before every push. Follow CONTRIBUTING.md for fixture,
  syntax and secret checks; run the Docker/pinned-harness checks when changing
  execution, permissions or provider protocols. Do not claim checks passed
  unless they were actually run.
- This hobby repository uses local verification. Do not add or enable GitHub
  Actions workflows unless the owner explicitly requests hosted CI again.
- Keep credentials, private deployment records and generated runtime state out
  of Git.
