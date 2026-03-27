# justfile for zorph-crypto crate publishing
#
# IMPORTANT: crates.io versions are IMMUTABLE. Once a version (e.g. 0.1.0) is
# published, it cannot be updated or overwritten. You MUST bump the version
# (e.g. to 0.1.1) before publishing any changes. A published version is
# permanent and cannot be modified or deleted.

# Default recipe: list available recipes
default:
    @just --list

# Run cargo check
check:
    cargo check --all-targets

# Run all tests
test:
    cargo test --all-targets

# Run benchmarks
bench:
    cargo bench

# Run clippy lints
lint:
    cargo clippy --all-targets -- -D warnings

# Check formatting (fails if not formatted)
fmt:
    cargo fmt --check

# Run cargo audit (requires cargo-audit: cargo install cargo-audit)
audit:
    @if command -v cargo-audit >/dev/null 2>&1; then \
        cargo audit; \
    else \
        echo "cargo-audit is not installed. Install with: cargo install cargo-audit"; \
        exit 1; \
    fi

# Run all pre-publish checks: check, test, lint, fmt
pre-publish: check test lint fmt

# Publish to crates.io (runs all pre-publish checks first)
publish: pre-publish
    cargo publish

# Dry-run publish (validates packaging without uploading)
publish-dry:
    cargo publish --dry-run

# Bump patch version in Cargo.toml (e.g. 0.1.0 -> 0.1.1)
bump-patch:
    #!/usr/bin/env bash
    set -euo pipefail
    current=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    IFS='.' read -r major minor patch <<< "$current"
    new_patch=$((patch + 1))
    new_version="${major}.${minor}.${new_patch}"
    sed -i '' "s/^version = \"${current}\"/version = \"${new_version}\"/" Cargo.toml
    echo "Bumped version: ${current} -> ${new_version}"

# Bump minor version in Cargo.toml (e.g. 0.1.0 -> 0.2.0)
bump-minor:
    #!/usr/bin/env bash
    set -euo pipefail
    current=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    IFS='.' read -r major minor patch <<< "$current"
    new_minor=$((minor + 1))
    new_version="${major}.${new_minor}.0"
    sed -i '' "s/^version = \"${current}\"/version = \"${new_version}\"/" Cargo.toml
    echo "Bumped version: ${current} -> ${new_version}"

# Bump major version in Cargo.toml (e.g. 0.1.0 -> 1.0.0)
bump-major:
    #!/usr/bin/env bash
    set -euo pipefail
    current=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    IFS='.' read -r major minor patch <<< "$current"
    new_major=$((major + 1))
    new_version="${new_major}.0.0"
    sed -i '' "s/^version = \"${current}\"/version = \"${new_version}\"/" Cargo.toml
    echo "Bumped version: ${current} -> ${new_version}"

# Full release: update version, commit, tag, and publish
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Releasing zorph-crypto v{{version}}"
    # Update version in Cargo.toml
    current=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    if [ "$current" = "{{version}}" ]; then
        echo "Version is already {{version}}"
    else
        sed -i '' "s/^version = \"${current}\"/version = \"{{version}}\"/" Cargo.toml
        echo "Updated Cargo.toml: ${current} -> {{version}}"
    fi
    # Run all pre-publish checks
    just pre-publish
    # Commit version change
    git add Cargo.toml Cargo.lock
    git commit -m "release: v{{version}}"
    # Create git tag
    git tag -a "v{{version}}" -m "Release v{{version}}"
    echo "Created tag v{{version}}"
    # Publish to crates.io
    cargo publish
    echo ""
    echo "Successfully released zorph-crypto v{{version}}"
    echo "Don't forget to push the tag: git push && git push --tags"
