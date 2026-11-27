#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

usage() {
  printf 'Usage: bash .github/scripts/update-shield-compatibility.sh [--dry-run]\n'
}

if (( $# > 1 )); then
  usage >&2
  exit 2
fi

dry_run=false
case "${1-}" in
  '') ;;
  --dry-run) dry_run=true ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

matrix='.github/shield-versions.json'
branch_prefix='automation/shield-compatibility-'
stable_pattern='\A(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}\z'

current=$(jq -ce --arg stable "$stable_pattern" '
  if type == "array" and length > 0 and all(.[]; type == "string" and test($stable))
  then .
  else error("The matrix must list exact stable Shield versions.")
  end
' "$matrix")
constraint=$(jq -er '.require["codeigniter4/shield"]' composer.json)
candidates=$(composer show --all --format=json --no-interaction --no-plugins --no-scripts codeigniter4/shield "$constraint" |
  jq -r --arg stable "$stable_pattern" --argjson current "$current" '
    [.versions[] | ltrimstr("v") | select(test($stable))]
    | (unique - $current) | sort_by(split(".") | map(tonumber)) | .[]
  ')

if [[ -z "$candidates" ]]; then
  printf 'The compatibility matrix includes every supported stable Shield release.\n'
  exit 0
fi

printf 'Shield releases missing from the matrix:\n%s\n' "$candidates"
if [[ "$dry_run" == true ]]; then
  exit 0
fi

: "${GH_TOKEN:?Set the SHIELD_COMPATIBILITY_TOKEN repository secret to open pull requests. See CONTRIBUTING.md.}"
repository=${GITHUB_REPOSITORY:?Set GITHUB_REPOSITORY to the repository name.}
owner=${repository%%/*}

open_heads=$(gh api --paginate "repos/$repository/pulls?state=open&base=main&per_page=100" \
  --jq '.[] | [.head.repo.full_name, .head.ref] | @tsv')
while IFS=$'\t' read -r head_repository head_branch; do
  if [[ "$head_repository" == "$repository" && "$head_branch" == "$branch_prefix"* ]]; then
    printf 'A Shield compatibility pull request is already open.\n'
    exit 0
  fi
done <<< "$open_heads"

publish_release() {
  local version=$1
  local branch="$branch_prefix$version"
  local ref="refs/heads/$branch"
  local versions remote head branch_versions contents

  versions=$(jq -c --arg version "$version" '. + [$version] | sort_by(split(".") | map(tonumber))' <<< "$current")
  remote=$(git ls-remote origin "$ref")
  if [[ -n "$remote" ]]; then
    head=${remote%%$'\t'*}
    branch_versions=$(gh api --method GET "repos/$repository/contents/$matrix" -f "ref=$head" --jq '.content' |
      jq -Rsce 'gsub("[[:space:]]"; "") | @base64d | fromjson')
    if [[ "$branch_versions" != "$current" && "$branch_versions" != "$versions" ]]; then
      printf 'Unexpected matrix contents in %s. Review the branch before retrying.\n' "$branch" >&2
      return 1
    fi
  else
    head=$(git rev-parse HEAD)
    gh api --method POST "repos/$repository/git/refs" -f "ref=$ref" -f "sha=$head" > /dev/null
    branch_versions=$current
  fi

  if [[ "$branch_versions" != "$versions" ]]; then
    contents=$(jq . <<< "$versions" | jq -Rsre '@base64')
    jq -n --arg repository "$repository" --arg branch "$branch" --arg head "$head" \
      --arg version "$version" --arg path "$matrix" --arg contents "$contents" '
      {
        query: "mutation AddShieldVersion($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }",
        variables: {input: {
          branch: {repositoryNameWithOwner: $repository, branchName: $branch},
          expectedHeadOid: $head,
          message: {headline: ("ci: test Shield " + $version)},
          fileChanges: {additions: [{path: $path, contents: $contents}]}
        }}
      }
    ' | gh api graphql --input - --jq '.data.createCommitOnBranch.commit.oid'
  fi

  gh pr create --repo "$repository" --base main --head "$branch" \
    --title "ci: test Shield $version" --body-file - <<EOF
Add Shield \`$version\` to the compatibility matrix on PHP 8.2.

Composer constraints in \`composer.json\` continue to apply. Review the compatibility checks before merging.
EOF
}

while IFS= read -r version; do
  prior=$(gh api --method GET "repos/$repository/pulls" \
    -f state=all -f base=main -f "head=$owner:$branch_prefix$version" -f per_page=1 --jq '.[].number')
  if [[ -z "$prior" ]]; then
    publish_release "$version"
    exit 0
  fi
done <<< "$candidates"

printf 'The missing releases already have a compatibility pull request.\n'
