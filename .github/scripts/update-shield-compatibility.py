"""Propose a matrix entry for a stable Shield release on Packagist."""

import argparse
import base64
import json
import os
import re
import subprocess
from pathlib import Path


MATRIX = Path(".github/shield-versions.json")
SHIELD = "codeigniter4/shield"
STABLE_VERSION = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")
BRANCH_PREFIX = "automation/shield-compatibility-"
COMMIT_QUERY = """
mutation AddShieldVersion($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid } }
}
"""


def capture(*command):
    return subprocess.check_output(command, text=True).strip()


def version_key(version):
    return tuple(map(int, version.split(".")))


def missing_releases(current):
    constraint = json.loads(Path("composer.json").read_text())["require"][SHIELD]
    package = json.loads(capture(
        "composer", "show", "--all", "--format=json", "--no-interaction",
        "--no-plugins", "--no-scripts", SHIELD, constraint,
    ))
    releases = (version.removeprefix("v") for version in package["versions"])
    stable = {version for version in releases if STABLE_VERSION.fullmatch(version)}
    return sorted(stable.difference(current), key=version_key)


def pending_release(repository, candidates):
    open_heads = capture(
        "gh", "api", "--paginate", f"repos/{repository}/pulls?state=open&base=main&per_page=100",
        "--jq", ".[] | [.head.repo.full_name, .head.ref] | @tsv",
    ).splitlines()
    if any(head.startswith(f"{repository}\t{BRANCH_PREFIX}") for head in open_heads):
        print("A Shield compatibility pull request is already open.")
        return None

    owner = repository.split("/", 1)[0]
    for version in candidates:
        prior = capture(
            "gh", "api", "--method", "GET", f"repos/{repository}/pulls",
            "-f", "state=all", "-f", "base=main", "-f", f"head={owner}:{BRANCH_PREFIX}{version}",
            "-f", "per_page=1", "--jq", ".[].number",
        )
        if not prior:
            return version

    print("The missing releases already have a compatibility pull request.")
    return None


def publish_release(repository, version, current):
    branch = BRANCH_PREFIX + version
    ref = f"refs/heads/{branch}"
    versions = sorted([*current, version], key=version_key)
    remote = capture("git", "ls-remote", "origin", ref)
    if remote:
        head = remote.split()[0]
        contents = capture(
            "gh", "api", "--method", "GET", f"repos/{repository}/contents/{MATRIX}",
            "-f", f"ref={head}", "--jq", ".content",
        )
        branch_versions = json.loads(base64.b64decode(contents))
        if branch_versions not in (current, versions):
            raise SystemExit(f"Unexpected matrix contents in {branch}. Review the branch before retrying.")
    else:
        head = capture("git", "rev-parse", "HEAD")
        capture(
            "gh", "api", "--method", "POST", f"repos/{repository}/git/refs",
            "-f", f"ref={ref}", "-f", f"sha={head}",
        )
        branch_versions = current

    if branch_versions != versions:
        matrix_contents = json.dumps(versions, indent=2) + "\n"
        request = {
            "query": COMMIT_QUERY,
            "variables": {"input": {
                "branch": {"repositoryNameWithOwner": repository, "branchName": branch},
                "expectedHeadOid": head,
                "message": {"headline": f"ci: test Shield {version}"},
                "fileChanges": {"additions": [{
                    "path": MATRIX.as_posix(),
                    "contents": base64.b64encode(matrix_contents.encode()).decode(),
                }]},
            }},
        }
        subprocess.run(
            ["gh", "api", "graphql", "--input", "-", "--jq", ".data.createCommitOnBranch.commit.oid"],
            input=json.dumps(request), text=True, check=True,
        )

    subprocess.run([
        "gh", "pr", "create", "--repo", repository, "--base", "main", "--head", branch,
        "--title", f"ci: test Shield {version}", "--body-file", "-",
    ], input=(
        f"Add Shield `{version}` to the compatibility matrix on PHP 8.2.\n\n"
        "Composer constraints in `composer.json` continue to apply. "
        "Review the compatibility checks before merging.\n"
    ), text=True, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="List missing versions without opening a pull request.")
    args = parser.parse_args()

    current = json.loads(MATRIX.read_text())
    if not isinstance(current, list) or not current or not all(
        isinstance(version, str) and STABLE_VERSION.fullmatch(version) for version in current
    ):
        raise SystemExit(f"{MATRIX} must list exact stable Shield versions.")

    candidates = missing_releases(current)
    if not candidates:
        print("The compatibility matrix includes every supported stable Shield release.")
        return

    print(f"Shield releases missing from the matrix: {', '.join(candidates)}", flush=True)
    if args.dry_run:
        return

    if not os.environ.get("GH_TOKEN"):
        raise SystemExit("Set the SHIELD_COMPATIBILITY_TOKEN repository secret to open pull requests. See CONTRIBUTING.md.")

    repository = os.environ["GITHUB_REPOSITORY"]
    version = pending_release(repository, candidates)
    if version is not None:
        publish_release(repository, version, current)


if __name__ == "__main__":
    main()
