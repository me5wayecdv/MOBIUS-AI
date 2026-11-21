"""HELD, unwired: refuses any egress of inspection/probe/staging output to an
audience that is not an explicitly reviewed PRIVATE one.

The repository is PUBLIC: workflow logs, job summaries, artifacts, PR comments and
issue text are public audiences. This gate validates a supplied plan record only.
It does not authenticate the destination, and it never grants permission.
"""
import re

APPROVED_FOR_EXECUTION=False
PRIVATE_AUDIENCES={'local_private_file','private_agent_channel'}
PUBLIC_OR_UNKNOWN={'workflow_log','job_summary','public_artifact','pr_comment','issue_comment','public_release','unknown'}
CONTENT_CLASSES={'package_hash_inventory','capability_metadata','test_result_booleans'}
FORBIDDEN_CLASSES={'user_data','credentials','device_logs','model_output','raw_member_bytes'}


def check_plan(plan):
    if not isinstance(plan,dict) or set(plan)!={'audience','destination','content_class','retention_days','reviewed_private_destination'}:
        raise ValueError('closed plan keys required')
    a,c=plan['audience'],plan['content_class']
    if not isinstance(a,str) or a in PUBLIC_OR_UNKNOWN or a not in PRIVATE_AUDIENCES:raise ValueError('reviewed private audience required')
    if not isinstance(c,str) or c in FORBIDDEN_CLASSES or c not in CONTENT_CLASSES:raise ValueError('closed content class required')
    r=plan['retention_days']
    if type(r) is not int or not 1<=r<=30:raise ValueError('bounded retention 1..30 days required')
    d=plan['destination']
    if not isinstance(d,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,200}',d) or '..' in d:raise ValueError('canonical absolute private destination required')
    if plan['reviewed_private_destination'] is not True:raise ValueError('destination review is a supplied fact; absent here')
    return True
