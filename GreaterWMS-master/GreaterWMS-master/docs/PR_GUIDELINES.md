# Pull Request Guidelines

## Branch Naming Convention

Use the following format for branch names:
```
<type>/<short-description>
```

### Branch Types
- `feature/` - New features or enhancements
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring without functional changes
- `test/` - Adding or updating tests
- `chore/` - Maintenance tasks, dependency updates

### Examples
- `feature/user-authentication`
- `fix/inventory-calculation-bug`
- `docs/api-documentation-update`
- `refactor/database-queries`

## Commit Message Style

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Commit Types
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, semicolons, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks
- `perf:` - Performance improvements
- `ci:` - CI/CD changes
- `build:` - Build system changes

### Examples
```
feat(auth): add user login functionality
fix(inventory): correct stock calculation error
docs: update API documentation
chore: update dependencies
```

### Breaking Changes
For breaking changes, add `!` after the type or include `BREAKING CHANGE:` in the footer:
```
feat!: change API response format
fix(api): correct user endpoint

BREAKING CHANGE: user endpoint now returns different response structure
```

## Code Review Process

### Before Creating a PR
1. **Self-review**: Review your own code thoroughly
2. **Tests**: Ensure all tests pass locally
3. **Linting**: Run code linters and fix any issues
4. **Documentation**: Update relevant documentation

### PR Requirements
- **Title**: Use descriptive title following conventional commit format
- **Description**: Fill out the PR template completely
- **Size**: Keep PRs focused and reasonably sized (< 400 lines when possible)
- **Tests**: Include tests for new functionality
- **Documentation**: Update docs for user-facing changes

### Reviewer Expectations
- **Response Time**: Reviewers should respond within 2 business days
- **Constructive Feedback**: Provide clear, actionable feedback
- **Approval**: At least one approval required before merging
- **Code Quality**: Review for readability, maintainability, and best practices

### Review Checklist
- [ ] Code follows project conventions
- [ ] Logic is sound and efficient
- [ ] Error handling is appropriate
- [ ] Tests cover new functionality
- [ ] Documentation is updated
- [ ] No obvious security issues
- [ ] Performance impact considered

## Merge Policy

### Protected Branch Rules
- **Required Reviews**: Minimum 1 approval from code owners
- **Status Checks**: All CI checks must pass
- **Up-to-date Branch**: Branch must be up-to-date with base branch
- **No Force Push**: Force pushes disabled on protected branches

### Merge Strategy
- **Squash and Merge**: Default for feature branches
  - Keeps clean commit history
  - Preserves PR context
- **Merge Commit**: For release branches and hotfixes
- **Rebase and Merge**: For small, clean commits

### Post-Merge
- **Delete Branch**: Delete feature branches after successful merge
- **Release Notes**: Ensure changes are captured for release notes
- **Deployment**: Follow deployment procedures for production changes

## Labels

Use these labels to categorize PRs:

### Type Labels
- `feature` - New features or enhancements
- `bug` - Bug fixes
- `docs` - Documentation updates
- `refactor` - Code refactoring
- `test` - Test additions/updates
- `chore` - Maintenance tasks

### Priority Labels
- `priority:high` - Critical fixes or important features
- `priority:medium` - Standard priority
- `priority:low` - Nice-to-have improvements

### Status Labels
- `needs-review` - Ready for review
- `needs-changes` - Requires changes before merge
- `ready-to-merge` - Approved and ready for merge
- `wip` - Work in progress

### Size Labels
- `size:small` - < 100 lines changed
- `size:medium` - 100-400 lines changed
- `size:large` - > 400 lines changed

## Best Practices

1. **Small, Focused PRs**: One logical change per PR
2. **Clear Descriptions**: Explain the what and why
3. **Test Coverage**: Maintain or improve test coverage
4. **Documentation**: Keep docs in sync with code changes
5. **Breaking Changes**: Highlight and document breaking changes
6. **Security**: Never commit secrets or sensitive data
7. **Performance**: Consider performance impact of changes
8. **Backwards Compatibility**: Maintain compatibility when possible