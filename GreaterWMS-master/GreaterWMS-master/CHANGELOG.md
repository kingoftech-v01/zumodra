# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New features that have been added since the last release

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Now removed features

### Fixed
- Any bug fixes

### Security
- In case of vulnerabilities

---

## [2.1.50] - 2024-XX-XX

### Added
- Example: New inventory management features
- Example: Enhanced user authentication system

### Changed
- Example: Updated API response format for better consistency

### Fixed
- Example: Fixed stock calculation errors in warehouse module
- Example: Resolved UI display issues on mobile devices

### Security
- Example: Updated dependencies to address security vulnerabilities

## [2.1.49] - 2024-XX-XX

### Added
- Example: Multi-language support for French users
- Example: New reporting dashboard

### Fixed
- Example: Fixed database connection timeout issues
- Example: Resolved memory leaks in background processes

---

## Guidelines for Maintaining the Changelog

### When to Update
- **Immediately** when merging PRs that affect users
- **Before each release** to ensure completeness
- **When fixing bugs** that were reported by users

### What to Include
- **User-facing changes**: Features, bug fixes, API changes
- **Security updates**: Vulnerability fixes, dependency updates
- **Breaking changes**: Changes that require user action
- **Performance improvements**: Significant performance gains

### What NOT to Include
- Internal refactoring that doesn't affect users
- CI/CD pipeline changes
- Code formatting or style changes
- Documentation updates (unless they reflect feature changes)

### Writing Guidelines
1. **Use clear, non-technical language** that users can understand
2. **Link to issues/PRs** where relevant: `- Fixed login bug (#123)`
3. **Group related changes** under appropriate categories
4. **Mention breaking changes prominently** in the Changed section
5. **Include migration instructions** for breaking changes

### Categories Explained
- **Added**: New features, APIs, or capabilities
- **Changed**: Modifications to existing features (including breaking changes)
- **Deprecated**: Features marked for removal in future versions
- **Removed**: Features that have been completely removed
- **Fixed**: Bug fixes and error corrections
- **Security**: Security-related fixes and improvements

### Release Process
1. Update the `[Unreleased]` section with new changes
2. Before release, move unreleased changes to a new version section
3. Add release date in YYYY-MM-DD format
4. Create a new empty `[Unreleased]` section
5. Update version links at the bottom if using comparison links

### Example Entry Format
```markdown
## [1.2.3] - 2024-01-15

### Added
- New user dashboard with customizable widgets (#145)
- API endpoint for bulk inventory updates (#156)

### Changed
- **BREAKING**: User authentication now requires email verification (#134)
- Improved performance of stock calculation by 40% (#142)

### Fixed
- Fixed crash when uploading large CSV files (#138)
- Resolved timezone display issues in reports (#149)

### Security
- Updated all dependencies to latest secure versions (#151)
```

### Semantic Versioning Guidelines
- **MAJOR** (X.0.0): Breaking changes that require user action
- **MINOR** (1.X.0): New features that are backwards compatible
- **PATCH** (1.1.X): Bug fixes and small improvements

### Automation
This project uses [release-drafter](https://github.com/release-drafter/release-drafter) to automatically generate release notes from merged PRs. The changelog should be updated manually to ensure accuracy and user-friendly language.