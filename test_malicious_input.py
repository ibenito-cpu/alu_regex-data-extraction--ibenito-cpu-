"""
Malicious Input Test Cases
This file contains examples of inputs that should be rejected by the security validation
"""

# Test Case 1: XSS Attack with Script Tag
malicious_test_1 = """
Contact us at support@example.com or visit <script>alert('XSS')</script> our website.
"""

# Test Case 2: SQL Injection Attempt
malicious_test_2 = """
User email: admin@site.com
Query: SELECT * FROM users WHERE email = "test'; DROP TABLE users; --"
"""

# Test Case 3: JavaScript Protocol XSS
malicious_test_3 = """
Click here: javascript:alert(document.cookie)
Contact: user@example.com
"""

# Test Case 4: Event Handler XSS
malicious_test_4 = """
Email: contact@company.com
Link: <a href="#" onclick="maliciousFunction()">Click</a>
"""

# Test Case 5: Path Traversal Attack
malicious_test_5 = """
User requested file: ../../etc/passwd
Email: attacker@malicious.com
"""

# Test Case 6: Code Execution Attempt
malicious_test_6 = """
Contact: admin@system.com
Command: eval(dangerous_code)
"""

# Test Case 7: Dangerous Protocol
malicious_test_7 = """
Customer email: user@example.com
Uploaded file: file:///etc/shadow
"""

# Test Case 8: Combined Attack
malicious_test_8 = """
Email: test@example.com
<script>fetch('data://text/javascript,alert(1)')</script>
"""

if __name__ == "__main__":
    from data_extractor import DataExtractor
    
    extractor = DataExtractor()
    
    test_cases = [
        ("XSS Script Tag", malicious_test_1),
        ("SQL Injection", malicious_test_2),
        ("JavaScript Protocol", malicious_test_3),
        ("Event Handler XSS", malicious_test_4),
        ("Path Traversal", malicious_test_5),
        ("Code Execution", malicious_test_6),
        ("Dangerous Protocol", malicious_test_7),
        ("Combined Attack", malicious_test_8)
    ]
    
    print("=" * 70)
    print("MALICIOUS INPUT SECURITY TEST")
    print("=" * 70)
    print()
    
    passed = 0
    failed = 0
    
    for name, test_input in test_cases:
        is_valid, error_msg = extractor.validate_input(test_input)
        
        if not is_valid:
            print(f"✓ PASS - {name}")
            print(f"  Status: Correctly rejected")
            print(f"  Reason: {error_msg}")
            passed += 1
        else:
            print(f"✗ FAIL - {name}")
            print(f"  Status: Should have been rejected but was accepted")
            failed += 1
        
        print()
    
    print("=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 70)