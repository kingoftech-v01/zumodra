#!/bin/bash

# make_pr.sh - Helper script to run tests and create a pull request
# Usage: ./scripts/make_pr.sh [target-branch] [pr-title]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_TARGET_BRANCH="master"
PYTHON_TESTS="python manage.py test"
LINT_COMMAND="flake8 ."
FRONTEND_TEST_DIR="./templates"
FRONTEND_TESTS="npm test"

# Functions
print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

check_git_status() {
    print_step "Checking git status..."
    
    if [[ -n $(git status --porcelain) ]]; then
        print_warning "You have uncommitted changes:"
        git status --short
        echo
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_error "Aborted by user"
            exit 1
        fi
    else
        print_success "Working directory is clean"
    fi
}

run_python_tests() {
    print_step "Running Python tests..."
    
    if command -v python &> /dev/null; then
        if [[ -f "manage.py" ]]; then
            $PYTHON_TESTS
            print_success "Python tests passed"
        else
            print_warning "No Django manage.py found, skipping Python tests"
        fi
    else
        print_warning "Python not found, skipping Python tests"
    fi
}

run_linting() {
    print_step "Running code linting..."
    
    # Python linting
    if command -v flake8 &> /dev/null && [[ -f "manage.py" ]]; then
        $LINT_COMMAND
        print_success "Python linting passed"
    else
        print_warning "flake8 not found or no Python project detected, skipping Python linting"
    fi
    
    # Frontend linting
    if [[ -d "$FRONTEND_TEST_DIR" ]] && [[ -f "$FRONTEND_TEST_DIR/package.json" ]]; then
        cd "$FRONTEND_TEST_DIR"
        if command -v npm &> /dev/null; then
            if npm list eslint &> /dev/null; then
                npm run lint
                print_success "Frontend linting passed"
            else
                print_warning "ESLint not configured, skipping frontend linting"
            fi
        fi
        cd - > /dev/null
    fi
}

run_frontend_tests() {
    print_step "Running frontend tests..."
    
    if [[ -d "$FRONTEND_TEST_DIR" ]] && [[ -f "$FRONTEND_TEST_DIR/package.json" ]]; then
        cd "$FRONTEND_TEST_DIR"
        if command -v npm &> /dev/null; then
            if npm list jest &> /dev/null || npm list vitest &> /dev/null; then
                $FRONTEND_TESTS
                print_success "Frontend tests passed"
            else
                print_warning "No test framework found, skipping frontend tests"
            fi
        fi
        cd - > /dev/null
    else
        print_warning "No frontend project found, skipping frontend tests"
    fi
}

check_gh_cli() {
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed"
        echo "Please install it from: https://cli.github.com/"
        echo "Or use 'hub' if available: https://hub.github.com/"
        exit 1
    fi
    
    # Check if authenticated
    if ! gh auth status &> /dev/null; then
        print_error "GitHub CLI is not authenticated"
        echo "Please run: gh auth login"
        exit 1
    fi
}

create_pull_request() {
    local target_branch="${1:-$DEFAULT_TARGET_BRANCH}"
    local pr_title="$2"
    local current_branch
    
    current_branch=$(git branch --show-current)
    
    if [[ "$current_branch" == "$target_branch" ]]; then
        print_error "Cannot create PR from $target_branch to itself"
        print_error "Please switch to a feature branch first"
        exit 1
    fi
    
    print_step "Creating pull request..."
    
    # If no title provided, derive from branch name
    if [[ -z "$pr_title" ]]; then
        pr_title=$(echo "$current_branch" | sed 's/-/ /g' | sed 's/\b\w/\U&/g')
        pr_title=$(echo "$pr_title" | sed 's/^Feature /feat: /' | sed 's/^Fix /fix: /' | sed 's/^Docs /docs: /')
    fi
    
    # Push current branch
    print_step "Pushing branch to origin..."
    git push -u origin "$current_branch"
    
    # Create PR using GitHub CLI
    gh pr create \
        --title "$pr_title" \
        --base "$target_branch" \
        --fill \
        --draft=false
    
    print_success "Pull request created successfully!"
    
    # Open PR in browser
    if command -v gh &> /dev/null; then
        print_step "Opening PR in browser..."
        gh pr view --web
    fi
}

show_help() {
    echo "Usage: $0 [options] [target-branch] [pr-title]"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --skip-tests   Skip running tests"
    echo "  --skip-lint    Skip linting"
    echo "  --draft        Create PR as draft"
    echo
    echo "Arguments:"
    echo "  target-branch  Target branch for PR (default: $DEFAULT_TARGET_BRANCH)"
    echo "  pr-title       Title for the pull request (derived from branch if not provided)"
    echo
    echo "Examples:"
    echo "  $0                           # Create PR to master with auto-generated title"
    echo "  $0 develop                   # Create PR to develop branch"
    echo "  $0 master \"feat: add user auth\" # Create PR with specific title"
    echo "  $0 --skip-tests develop      # Skip tests and create PR to develop"
}

# Main execution
main() {
    local skip_tests=false
    local skip_lint=false
    local target_branch="$DEFAULT_TARGET_BRANCH"
    local pr_title=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --skip-tests)
                skip_tests=true
                shift
                ;;
            --skip-lint)
                skip_lint=true
                shift
                ;;
            --draft)
                # This would need to be handled in create_pull_request function
                print_warning "Draft PR option not yet implemented"
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$target_branch" ]] || [[ "$target_branch" == "$DEFAULT_TARGET_BRANCH" ]]; then
                    target_branch="$1"
                elif [[ -z "$pr_title" ]]; then
                    pr_title="$1"
                else
                    print_error "Too many arguments"
                    show_help
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    echo "🚀 PR Creation Helper"
    echo "===================="
    echo
    
    # Check prerequisites
    check_gh_cli
    check_git_status
    
    # Run tests and linting
    if [[ "$skip_tests" == false ]]; then
        run_python_tests
        run_frontend_tests
    else
        print_warning "Skipping tests as requested"
    fi
    
    if [[ "$skip_lint" == false ]]; then
        run_linting
    else
        print_warning "Skipping linting as requested"
    fi
    
    # Create PR
    create_pull_request "$target_branch" "$pr_title"
    
    print_success "All done! 🎉"
}

# Run main function with all arguments
main "$@"