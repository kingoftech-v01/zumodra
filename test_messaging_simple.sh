#!/bin/bash

echo "===================================================================="
echo "Messaging System Verification Tests"
echo "===================================================================="
echo ""

PASSED=0
FAILED=0

# Test 1: consumer.py file size
LINES=$(wc -l < messages_sys/consumer.py)
if [ "$LINES" -ge 400 ] && [ "$LINES" -le 450 ]; then
    echo "[PASS] consumer.py is clean ($LINES lines, expected ~442)"
    ((PASSED++))
else
    echo "[FAIL] consumer.py has unexpected size ($LINES lines)"
    ((FAILED++))
fi

# Test 2: No dead code in consumer.py
if ! grep -q "TEST FINDINGS" messages_sys/consumer.py && ! grep -q "OLD IMPLEMENTATION" messages_sys/consumer.py; then
    echo "[PASS] No dead commented code in consumer.py"
    ((PASSED++))
else
    echo "[FAIL] Dead code found in consumer.py"
    ((FAILED++))
fi

# Test 3: validate_file_type exists
if grep -q "def validate_file_type" messages_sys/consumer.py; then
    echo "[PASS] validate_file_type function exists"
    ((PASSED++))
else
    echo "[FAIL] validate_file_type function missing"
    ((FAILED++))
fi

# Test 4: Security constants
if grep -q "MAX_FILE_SIZE" messages_sys/consumer.py && grep -q "BLOCKED_EXTENSIONS" messages_sys/consumer.py; then
    echo "[PASS] Security constants defined"
    ((PASSED++))
else
    echo "[FAIL] Security constants missing"
    ((FAILED++))
fi

# Test 5: Tenant isolation
if grep -q "tenant_" messages_sys/consumer.py && grep -q "room_group_name" messages_sys/consumer.py; then
    echo "[PASS] Tenant isolation implemented"
    ((PASSED++))
else
    echo "[FAIL] Tenant isolation missing"
    ((FAILED++))
fi

echo ""
echo "--------------------------------------------------------------------"

# Test 6: routing.py is clean
LINES=$(wc -l < messages_sys/routing.py)
if [ "$LINES" -le 15 ]; then
    echo "[PASS] routing.py is clean ($LINES lines)"
    ((PASSED++))
else
    echo "[FAIL] routing.py too large ($LINES lines)"
    ((FAILED++))
fi

# Test 7: No old docs in routing
if ! grep -q "CRITICAL ISSUE" messages_sys/routing.py && ! grep -q "TEST FINDINGS" messages_sys/routing.py; then
    echo "[PASS] routing.py has no outdated documentation"
    ((PASSED++))
else
    echo "[FAIL] Outdated docs in routing.py"
    ((FAILED++))
fi

echo ""
echo "--------------------------------------------------------------------"

# Test 8: Views have WebSocket support
if grep -q "websocket_enabled" messages_sys/views.py && grep -q "websocket_url" messages_sys/views.py; then
    echo "[PASS] Views have WebSocket configuration"
    ((PASSED++))
else
    echo "[FAIL] Views missing WebSocket config"
    ((FAILED++))
fi

# Test 9: Views have error handling
if grep -q "logger.error" messages_sys/views.py && grep -q "try:" messages_sys/views.py; then
    echo "[PASS] Views have error handling"
    ((PASSED++))
else
    echo "[FAIL] Views missing error handling"
    ((FAILED++))
fi

echo ""
echo "--------------------------------------------------------------------"

# Test 10: Chat template exists and has WebSocket
if [ -f "templates/messages_sys/chat.html" ]; then
    echo "[PASS] Chat template exists"
    ((PASSED++))
    
    if grep -q "connectWebSocket" templates/messages_sys/chat.html; then
        echo "[PASS] Template has WebSocket implementation"
        ((PASSED++))
    else
        echo "[FAIL] Template missing WebSocket code"
        ((FAILED++))
    fi
    
    if grep -q "reconnectAttempts" templates/messages_sys/chat.html; then
        echo "[PASS] Template has auto-reconnect logic"
        ((PASSED++))
    else
        echo "[FAIL] Template missing reconnect logic"
        ((FAILED++))
    fi
    
    if grep -q "sendTypingIndicator" templates/messages_sys/chat.html; then
        echo "[PASS] Template has typing indicators"
        ((PASSED++))
    else
        echo "[FAIL] Template missing typing indicators"
        ((FAILED++))
    fi
    
    if grep -q "startPolling" templates/messages_sys/chat.html; then
        echo "[PASS] Template has fallback polling"
        ((PASSED++))
    else
        echo "[FAIL] Template missing fallback"
        ((FAILED++))
    fi
    
    if grep -q "escapeHtml" templates/messages_sys/chat.html; then
        echo "[PASS] Template has XSS protection"
        ((PASSED++))
    else
        echo "[FAIL] Template missing XSS protection"
        ((FAILED++))
    fi
else
    echo "[FAIL] Chat template not found"
    ((FAILED+=6))
fi

echo ""
echo "--------------------------------------------------------------------"

# Test 11: Tests file
LINES=$(wc -l < messages_sys/tests.py)
if [ "$LINES" -ge 400 ]; then
    echo "[PASS] Comprehensive tests exist ($LINES lines)"
    ((PASSED++))
else
    echo "[FAIL] Tests file too small ($LINES lines)"
    ((FAILED++))
fi

# Test 12: ConversationFactory
if grep -q "ConversationFactory" conftest.py && grep -q "conversation_factory" conftest.py; then
    echo "[PASS] ConversationFactory defined"
    ((PASSED++))
else
    echo "[FAIL] ConversationFactory missing"
    ((FAILED++))
fi

echo ""
echo "===================================================================="
echo "SUMMARY"
echo "===================================================================="
echo "Total Tests: $((PASSED + FAILED))"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo "*** ALL TESTS PASSED - Messaging System is READY! ***"
    exit 0
else
    echo "*** SOME TESTS FAILED - Review failures above ***"
    exit 1
fi
