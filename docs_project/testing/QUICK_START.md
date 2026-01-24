# Document Management System - Quick Start Guide

## What's New

You now have a complete, production-ready test suite for the Zumodra document management system. This guide gets you started in 5 minutes.

## Files You Need to Know About

1. **run_document_tests.py** - The automated test runner
2. **TESTING_INSTRUCTIONS.md** - Complete setup guide
3. **DOCUMENT_MANAGEMENT_TEST_GUIDE.md** - Manual testing guide

## 5-Minute Quick Start

```bash
# 1. Install dependencies
pip install requests

# 2. Start Docker services
docker compose up -d

# 3. Run tests
python tests_comprehensive/run_document_tests.py

# 4. Check results
cat tests_comprehensive/reports/document_management_test_report.json
```

## What Gets Tested

- Document upload (PDF, DOCX, PNG, etc.)
- Document categorization
- Document search
- E-signature workflows
- Document expiration
- Access control
- Document templates
- Document filtering

## Understanding Results

**Success Rate Target:** 90%+ (27+ out of 30 tests passing)

If you see:
- ✓ PASS - Test passed, feature working correctly
- ✗ FAIL - Test failed, check the error message
- ⊘ SKIP - Test was skipped (not critical)

## Common Commands

```bash
# Run tests normally
python tests_comprehensive/run_document_tests.py

# Run with verbose output
python tests_comprehensive/run_document_tests.py --verbose

# Run against different server
python tests_comprehensive/run_document_tests.py --base-url http://server:8002

# View results
cat tests_comprehensive/reports/document_management_test_report.json | python -m json.tool
```

## Troubleshooting

### Connection refused?
```bash
docker compose ps
docker compose up -d
```

### Tests failing?
Check the JSON report:
```bash
cat tests_comprehensive/reports/document_management_test_report.json
```

### Need help?
Read the appropriate guide:
- Setup: TESTING_INSTRUCTIONS.md
- Manual testing: DOCUMENT_MANAGEMENT_TEST_GUIDE.md
- Full details: README_TESTS.md

## File Locations

All test files are in:
```
tests_comprehensive/
├── run_document_tests.py          (automated tests)
├── TESTING_INSTRUCTIONS.md        (setup guide)
├── DOCUMENT_MANAGEMENT_TEST_GUIDE.md (manual tests)
├── README_TESTS.md                (full docs)
└── reports/                       (test results)
```

## Expected Success Metrics

- 30 total tests
- 27+ should pass
- 2-3 may be skipped
- Execution time: 2-5 minutes

## Next Steps

1. Run: `python tests_comprehensive/run_document_tests.py`
2. Check results in: `tests_comprehensive/reports/document_management_test_report.json`
3. For details: Read `TESTING_INSTRUCTIONS.md`
4. For manual testing: Follow `DOCUMENT_MANAGEMENT_TEST_GUIDE.md`

---

**Ready to start?** Run the tests now!

```bash
python tests_comprehensive/run_document_tests.py
```
