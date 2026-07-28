import os
import pytest
import yaml
from gh_actions_scanner.scanner import Scanner

@pytest.fixture
def scanner():
    return Scanner()

def test_pull_request_target_used(scanner, tmp_path):
    workflow_content = {
        'name': 'Test Workflow',
        'on': 'pull_request_target',
        'jobs': {'build': {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'echo hello'}]}}
    }

    filepath = tmp_path / "test.yml"
    with open(filepath, 'w') as f:
        yaml.dump(workflow_content, f)

    results = scanner.scan_file(str(filepath))
    assert len(results) == 1
    assert results[0]['rule'] == 'pull_request_target_used'
    assert results[0]['severity'] == 'HIGH'

def test_write_all_permissions_global(scanner, tmp_path):
    workflow_content = {
        'name': 'Test Workflow',
        'on': 'push',
        'permissions': 'write-all',
        'jobs': {'build': {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'echo hello'}]}}
    }

    filepath = tmp_path / "test.yml"
    with open(filepath, 'w') as f:
        yaml.dump(workflow_content, f)

    results = scanner.scan_file(str(filepath))
    assert len(results) == 1
    assert results[0]['rule'] == 'overly_permissive_token'
    assert results[0]['severity'] == 'CRITICAL'

def test_write_all_permissions_job(scanner, tmp_path):
    workflow_content = {
        'name': 'Test Workflow',
        'on': 'push',
        'jobs': {
            'build': {
                'runs-on': 'ubuntu-latest',
                'permissions': 'write-all',
                'steps': [{'run': 'echo hello'}]
            }
        }
    }

    filepath = tmp_path / "test.yml"
    with open(filepath, 'w') as f:
        yaml.dump(workflow_content, f)

    results = scanner.scan_file(str(filepath))
    assert len(results) == 1
    assert results[0]['rule'] == 'overly_permissive_token'
    assert results[0]['severity'] == 'CRITICAL'

def test_unpinned_action(scanner, tmp_path):
    workflow_content = {
        'name': 'Test Workflow',
        'on': 'push',
        'jobs': {
            'build': {
                'runs-on': 'ubuntu-latest',
                'steps': [{'uses': 'actions/checkout@v2'}]
            }
        }
    }

    filepath = tmp_path / "test.yml"
    with open(filepath, 'w') as f:
        yaml.dump(workflow_content, f)

    results = scanner.scan_file(str(filepath))
    assert len(results) == 1
    assert results[0]['rule'] == 'unpinned_third_party_action'
    assert results[0]['severity'] == 'MEDIUM'

def test_pinned_action(scanner, tmp_path):
    workflow_content = {
        'name': 'Test Workflow',
        'on': 'push',
        'jobs': {
            'build': {
                'runs-on': 'ubuntu-latest',
                'steps': [{'uses': 'actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332'}]
            }
        }
    }

    filepath = tmp_path / "test.yml"
    with open(filepath, 'w') as f:
        yaml.dump(workflow_content, f)

    results = scanner.scan_file(str(filepath))
    assert len(results) == 0

def test_script_injection(scanner, tmp_path):
    workflow_content = {
        'name': 'Test Workflow',
        'on': 'issue_comment',
        'jobs': {
            'build': {
                'runs-on': 'ubuntu-latest',
                'steps': [{'run': 'echo "Issue title is ${{ github.event.issue.title }}"'}]
            }
        }
    }

    filepath = tmp_path / "test.yml"
    with open(filepath, 'w') as f:
        yaml.dump(workflow_content, f)

    results = scanner.scan_file(str(filepath))
    assert len(results) == 1
    assert results[0]['rule'] == 'script_injection'
    assert results[0]['severity'] == 'HIGH'

def test_secure_workflow(scanner, tmp_path):
    workflow_content = {
        'name': 'Secure Workflow',
        'on': ['push', 'pull_request'],
        'permissions': {'contents': 'read'},
        'jobs': {
            'build': {
                'runs-on': 'ubuntu-latest',
                'steps': [
                    {'uses': 'actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332'},
                    {'run': 'echo "Safe to run"'}
                ]
            }
        }
    }

    filepath = tmp_path / "test.yml"
    with open(filepath, 'w') as f:
        yaml.dump(workflow_content, f)

    results = scanner.scan_file(str(filepath))
    assert len(results) == 0
