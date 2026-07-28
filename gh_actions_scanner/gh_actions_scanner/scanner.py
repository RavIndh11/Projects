import yaml
import os
import re

class Scanner:
    def __init__(self):
        self.rules = [
            self.check_pull_request_target,
            self.check_write_all_permissions,
            self.check_unpinned_actions,
            self.check_script_injection
        ]

    def scan_file(self, filepath):
        results = []
        try:
            with open(filepath, 'r') as f:
                # Use SafeLoader to avoid arbitrary code execution
                workflow = yaml.safe_load(f)

            if not isinstance(workflow, dict):
                return results

            for rule in self.rules:
                findings = rule(workflow, filepath)
                if findings:
                    results.extend(findings)

        except Exception as e:
            results.append({
                'file': filepath,
                'rule': 'parse_error',
                'severity': 'ERROR',
                'message': f"Failed to parse YAML: {str(e)}"
            })

        return results

    def check_pull_request_target(self, workflow, filepath):
        findings = []
        on_clause = workflow.get('on', {})

        has_pr_target = False
        if isinstance(on_clause, list):
            has_pr_target = 'pull_request_target' in on_clause
        elif isinstance(on_clause, dict):
            has_pr_target = 'pull_request_target' in on_clause
        elif isinstance(on_clause, str):
            has_pr_target = on_clause == 'pull_request_target'

        if has_pr_target:
            findings.append({
                'file': filepath,
                'rule': 'pull_request_target_used',
                'severity': 'HIGH',
                'message': 'Use of pull_request_target can lead to secret exfiltration or RCE if workflow runs untrusted code.'
            })
        return findings

    def check_write_all_permissions(self, workflow, filepath):
        findings = []

        # Check top-level permissions
        permissions = workflow.get('permissions', {})
        if permissions == 'write-all':
            findings.append({
                'file': filepath,
                'rule': 'overly_permissive_token',
                'severity': 'CRITICAL',
                'message': 'Global permissions set to write-all. Use principle of least privilege.'
            })

        # Check job-level permissions
        jobs = workflow.get('jobs', {})
        if isinstance(jobs, dict):
            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                job_permissions = job_data.get('permissions', {})
                if job_permissions == 'write-all':
                    findings.append({
                        'file': filepath,
                        'rule': 'overly_permissive_token',
                        'severity': 'CRITICAL',
                        'message': f"Job '{job_name}' permissions set to write-all. Use principle of least privilege."
                    })
        return findings

    def check_unpinned_actions(self, workflow, filepath):
        findings = []
        jobs = workflow.get('jobs', {})
        if not isinstance(jobs, dict):
            return findings

        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            steps = job_data.get('steps', [])
            if not isinstance(steps, list):
                continue

            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                uses = step.get('uses')
                if uses:
                    # Ignore local actions
                    if uses.startswith('./'):
                        continue

                    # Check if pinned to SHA
                    if not re.search(r'@[a-f0-9]{40}$', uses):
                        findings.append({
                            'file': filepath,
                            'rule': 'unpinned_third_party_action',
                            'severity': 'MEDIUM',
                            'message': f"Job '{job_name}', step {i+1} uses unpinned action '{uses}'. Pin to a full commit SHA."
                        })
        return findings

    def check_script_injection(self, workflow, filepath):
        findings = []
        jobs = workflow.get('jobs', {})
        if not isinstance(jobs, dict):
            return findings

        # Vulnerable contexts based on GitHub Actions documentation
        vuln_contexts = [
            r'github\.event\.issue\.title',
            r'github\.event\.issue\.body',
            r'github\.event\.pull_request\.title',
            r'github\.event\.pull_request\.body',
            r'github\.event\.comment\.body',
            r'github\.event\.review\.body',
            r'github\.event\.pages.*\.page_name',
            r'github\.event\.commits.*\.message',
            r'github\.head_ref',
            r'github\.base_ref'
        ]

        pattern = re.compile(r'\${{\s*(' + '|'.join(vuln_contexts) + r')\s*}}')

        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            steps = job_data.get('steps', [])
            if not isinstance(steps, list):
                continue

            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                run = step.get('run', '')
                if isinstance(run, str) and pattern.search(run):
                    findings.append({
                        'file': filepath,
                        'rule': 'script_injection',
                        'severity': 'HIGH',
                        'message': f"Job '{job_name}', step {i+1} uses a potentially untrusted context in a 'run' block. This can lead to script injection/RCE."
                    })
        return findings

def scan_directory(directory):
    scanner = Scanner()
    all_results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                filepath = os.path.join(root, file)
                all_results.extend(scanner.scan_file(filepath))
    return all_results
