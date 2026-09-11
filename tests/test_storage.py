import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.db import log_finding, get_all_findings

def test_log_and_retrieve():
    log_finding("network", "warning", "test-source", "This is a test finding")
    results = get_all_findings()
    assert len(results) > 0
    assert results[0].message == "This is a test finding"