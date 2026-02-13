# Exclude test_results directory from pytest collection - these are standalone scripts
collect_ignore_glob = ["test_results/*"]
collect_ignore = ["integration/test_api_simple.py"]
