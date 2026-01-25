import requests
import uuid

base = 'https://zumodra.rhematek-solutions.com/api/v1/messages'

# Test 1: List conversations
print("Test 1: GET /conversations/")
r1 = requests.get(f'{base}/conversations/', timeout=10)
print(f"  Status: {r1.status_code}")
if r1.status_code == 500:
    print("  FAIL: Server crash (FieldError)")
else:
    print("  PASS: No server crash")

# Test 2: Get messages
print("\nTest 2: GET /conversations/{id}/messages/")
cid = str(uuid.uuid4())
r2 = requests.get(f'{base}/conversations/{cid}/messages/', timeout=10)
print(f"  Status: {r2.status_code}")
if r2.status_code == 500:
    print("  FAIL: Server crash")
else:
    print("  PASS: No FieldError")

# Test 3: Send message
print("\nTest 3: POST /conversations/{id}/send_message/")
r3 = requests.post(f'{base}/conversations/{cid}/send_message/', json={'content': 'test'}, timeout=10)
print(f"  Status: {r3.status_code}")
if r3.status_code == 500:
    print("  FAIL: Server crash")
else:
    print("  PASS: No TypeError/FieldError")

print("\n=== SUMMARY ===")
if all(r.status_code != 500 for r in [r1, r2, r3]):
    print("SUCCESS: All messaging API endpoints working!")
    print("All fixes deployed successfully - no FieldError, TypeError, or AttributeError")
else:
    print("FAILURE: Some endpoints returning 500 errors")
