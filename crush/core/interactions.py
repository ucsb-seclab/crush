from crush.target import Target
from crush.sql import run_query


def run_interaction_analysis(self_address):
    # first confirm that there is at least one delegatecall
    proxy_project = Target.project_at(self_address)
    assert any([s.__internal_name__ == "DELEGATECALL" for id, s in proxy_project.statement_at.items()]), "No delegatecall found in proxy"

    # find known interactions
    result = run_query(f"select receiver from internal_transactions where call_type = 'delegatecall' and sender = '{self_address}' group by receiver;")
    receivers = [r[0] for r in result]

    return receivers