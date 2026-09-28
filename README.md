# COSAC Lab Security Agents

AWS lab demonstrations of how security-agent policy changes affect real outcomes.
Each scenario runs two agents using the same code and model, with one policy
configuration difference. TRACE means **Trace, Record, Authorize, Constrain,
Escalate**; policy checks happen outside the model.

| Scenario | Task | Deliberately flawed profile | Guarded profile |
| --- | --- | --- | --- |
| A — Warden | Block scanning sources in AWS WAF | `WARDEN_POLICY_PROFILE=legacy` | `WARDEN_POLICY_PROFILE=enforcing` |
| B — Custodian | Quarantine EC2 instances after GuardDuty findings | `CUSTODIAN_ESCALATION_PROFILE=approval_gated` | `CUSTODIAN_ESCALATION_PROFILE=non_blocking` |

Warden demonstrates overly broad blocking that can lock out responders.
Custodian demonstrates the cost of waiting for approval before containment.
The scoreboard displays responder reachability, containment, and synthetic data
exfiltration. Live mode uses AWS resources; rehearsal mode uses scripted data.

## Requirements and local setup

- Python 3.11 or newer, with `pip` and virtual-environment support.
- For live use: AWS CLI, authenticated GitHub CLI (`gh`), and a dedicated AWS
  lab account with permissions to deploy the included infrastructure and access
  the Bedrock model configured in `infra/stacks/*/variables.tf`.
- The deployment workflows install Terraform and build the agent packages.
  Local Terraform is only needed if you run the infrastructure manually.

```bash
git clone https://github.com/fouadmulla/cosac-lab-security-agents.git
cd cosac-lab-security-agents
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
ruff check agents tests demo
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. The deployment examples
below use Bash syntax.

Preview the scoreboard without AWS credentials or deployed resources:

```bash
python demo/scoreboard.py --rehearse
```

Open <http://localhost:8900>. Keys: `1`/`2` switch scenarios, `f` enters full
screen, `r` clears the board, and `R` resets the lab in live mode. In rehearsal,
both reset keys restart the scripted demonstration.

## One-time AWS and GitHub setup

The examples use `us-east-1` and an AWS SSO profile named `cosac`. Configure that
profile for your lab account first. Repository variables, environments, and AWS
trust relationships must be configured for this new repository.

```bash
gh auth login
export GH_REPO=fouadmulla/cosac-lab-security-agents
export AWS_PROFILE=cosac
export AWS_REGION=us-east-1
aws sso login --profile "$AWS_PROFILE"
aws sts get-caller-identity

aws cloudformation deploy \
  --template-file infra/bootstrap/bootstrap.yaml \
  --stack-name cosac-bootstrap \
  --region "$AWS_REGION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOrg=fouadmulla RepoName=cosac-lab-security-agents
```

The bootstrap creates shared state storage, IAM roles, the decision ledger,
approval infrastructure, and the lab expiry reaper. Resource and package names
retain the original `cosac` naming. Use a separate lab account for an independent
deployment: the template uses fixed names and is not designed for two copies in
one account.

If the account already has the GitHub OIDC provider, add
`CreateOIDCProvider=false` to the parameter overrides. If your GitHub OIDC
subject uses immutable numeric IDs, also add `GitHubOwnerId=69036879` and
`GitHubRepoId=1379886292` for this repository; leave them unset for name-based
subjects. The template's original repository default is unchanged, so keep the
explicit `RepoName=cosac-lab-security-agents` override.

Read the bootstrap outputs:

```bash
aws cloudformation describe-stacks --stack-name cosac-bootstrap \
  --query 'Stacks[0].Outputs' --output table
```

In this repository's **Settings → Secrets and variables → Actions → Variables**,
set the following repository variables. These are configuration values, not
static AWS access keys; the workflows authenticate with OIDC.

| Variable | Value / bootstrap output |
| --- | --- |
| `AWS_REGION` | `us-east-1` |
| `TF_STATE_BUCKET` | `StateBucketName` |
| `AWS_PLAN_ROLE_ARN` | `PlanRoleArn` |
| `AWS_APPLY_ROLE_ARN` | `ApplyRoleArn` |
| `AWS_DEMO_ROLE_ARN` | `DemoRoleArn` |
| `AWS_TEARDOWN_ROLE_ARN` | `TeardownRoleArn` |

Create **Settings → Environments → `lab-plan`** and **`lab-apply`**. Configure
required reviewers on `lab-apply` if available for your repository, and verify
the protection is active before deploying. The workflow's environment label
alone does not require a human review. The apply role's trust policy requires
the `lab-apply` environment.

## Deploy and run

Run these commands from the checkout, with `GH_REPO`, `AWS_PROFILE`, and
`AWS_REGION` set as above. You can also select the same workflows and inputs in
the repository's **Actions** tab.

```bash
gh workflow run deploy -f stack=scenario-a -f action=plan
gh workflow run deploy -f stack=scenario-b -f action=plan

gh workflow run deploy -f stack=scenario-a -f action=apply -f ttl_hours=2
gh workflow run deploy -f stack=scenario-b -f action=apply -f ttl_hours=2
```

Wait for both apply runs to finish successfully and approve their environment
reviews when requested. Each workflow reports its Terraform outputs. Then start
the live scoreboard in a separate terminal:

```bash
python demo/scoreboard.py --profile cosac --region us-east-1 \
  --repo fouadmulla/cosac-lab-security-agents
```

Start Custodian first because GuardDuty detection and event delivery take time.
Then run Warden's scanning stage; wait for that workflow to finish and observe
the agents' decisions before starting stage 2.

```bash
gh workflow run "agent custodian" -f phase=compromise
gh workflow run "agent warden" -f phase=stage-1
# After stage 1 completes and the scoreboard reflects its results:
gh workflow run "agent warden" -f phase=stage-2
```

The live scoreboard uses your AWS profile. Approval buttons write decisions
using the operator's credentials and can trigger containment. `R` dispatches
both reset workflows through `gh` and waits for GitHub and AWS to confirm the
reset. Use credentials authorized for these lab operations.

## Reset, emergency containment, and teardown

Reset between runs; Custodian reset stops the test payload and returns victims
to their normal security group. It releases containment.

```bash
gh workflow run "agent warden" -f phase=reset
gh workflow run "agent custodian" -f phase=reset
```

For emergency containment, use `contain-now` to quarantine both Custodian
victims. Warden reset clears its WAF blocks.

```bash
gh workflow run "agent custodian" -f phase=contain-now
gh workflow run "agent warden" -f phase=reset
```

Destroy both scenario stacks when finished and verify the workflow results:

```bash
gh workflow run deploy -f stack=scenario-a -f action=destroy
gh workflow run deploy -f stack=scenario-b -f action=destroy
```

Deployment defaults to a two-hour expiry. The bootstrap reaper checks deadlines
every ten minutes and deletes running lab resources after expiry; if it fires,
run the destroy workflows afterward to reconcile Terraform state. The nightly
teardown is scheduled for 04:00 UTC when `AWS_TEARDOWN_ROLE_ARN` is configured
and `KEEP_STACKS_OVERNIGHT` is not `true`. That variable does not disable the
separate expiry reaper. These mechanisms are backstops: check that cleanup
actually completed. Bootstrap resources and retained data can continue to incur
charges after the scenario stacks are destroyed.

## Repository layout

- `agents/` — agent loops, handlers, policy checks, provenance, and execution.
- `infra/bootstrap/` — shared CloudFormation bootstrap.
- `infra/stacks/scenario-a/` and `scenario-b/` — Terraform lab infrastructure.
- `demo/` — scoreboard and agent package builder.
- `tests/` — automated policy and agent tests.
- `.github/workflows/` — CI, deployment, scenario triggers, and teardown.

## Disclaimer and license

This is educational lab software with intentionally flawed security policies.
Run it only in an isolated AWS account on assets you own or are explicitly
authorized to test. Do not deploy it into production or an account containing
real workloads or sensitive data. Live workflows generate attack-like traffic,
change WAF rules and EC2 networking, and can interrupt access. Use synthetic
data, monitor charges, and tear down resources after use. Rehearsal results are
scripted and are not evidence of a live deployment.

The software is provided as is, without warranty. You are responsible for
deployment, permissions, use, and costs. Copyright (c) 2026 Fouad Mulla.
Distributed under the [MIT License](LICENSE); retain its copyright and permission
notice when redistributing.
