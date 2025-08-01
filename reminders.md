# Build Reminders

- The project is pinned to `base64ct = 1.7.3` in `Cargo.lock` and `[workspace.dependencies]` (edition-2021).
  - Reason: version 1.8.0 requires `edition2024`, which stable Rust (≤1.84) cannot compile.
  - When upgrading to nightly or when edition 2024 stabilises, remove the pin:
    ```zsh
    cargo update -p base64ct           # grabs latest
    # or specify a precise newer version
    cargo update -p base64ct --precise 1.8.0
    ```
  - If the lock-file gets regenerated, re-apply the pin:
    ```zsh
    cargo update -p base64ct --precise 1.7.3
    ```

- Keep `.cargo/config.toml` or `Cargo.toml` override in sync with future base64ct changes. 