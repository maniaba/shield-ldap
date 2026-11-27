"""Build the User Guide Pages artifact and update the local mike history."""

import json
import re
import subprocess
import sys
import tarfile
from html import escape
from pathlib import Path
from posixpath import relpath
from tempfile import TemporaryDirectory, TemporaryFile


STABLE_VERSION = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")


def capture(*command):
    return subprocess.check_output(command, text=True).strip()


def run(*command, cwd=None):
    subprocess.run(command, cwd=cwd, check=True)


def version_number(version):
    return tuple(map(int, version.split(".")))


def stable_tags():
    tags = capture("git", "tag", "--list", "v*").splitlines()
    return sorted(
        (tag for tag in tags if STABLE_VERSION.fullmatch(tag[1:])),
        key=lambda tag: version_number(tag[1:]),
    )


def published_versions():
    return {entry["version"]: entry for entry in json.loads(capture("mike", "list", "--json"))}


def deploy_release(version, tag):
    with TemporaryDirectory() as workspace:
        source = Path(workspace) / "release"
        run("git", "worktree", "add", "--detach", str(source), f"refs/tags/{tag}")
        try:
            run("mike", "deploy", version, cwd=source)
        finally:
            run("git", "worktree", "remove", str(source))


def export_site(output, version):
    output.mkdir(parents=True)
    with TemporaryFile() as archive:
        subprocess.run(["git", "archive", "gh-pages"], stdout=archive, check=True)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as site:
            site.extractall(output, filter="data")

    version_root = output / "latest"
    latest_index = version_root / "index.html"
    selected_index = output / version / "index.html"
    if not latest_index.is_file() or latest_index.read_bytes() != selected_index.read_bytes():
        raise RuntimeError(f"The /latest/ guide does not match the selected version {version}.")

    # Keep public URLs that predate versioned documentation working.
    for page in version_root.rglob("*/index.html"):
        relative = page.relative_to(version_root)
        legacy_page = output / relative
        if legacy_page.exists():
            continue
        target = escape(relpath(Path("latest") / relative.parent, relative.parent) + "/")
        legacy_page.parent.mkdir(parents=True, exist_ok=True)
        legacy_page.write_text(
            '<!doctype html>\n<html lang="en"><meta charset="utf-8">\n'
            '<title>Redirecting to the Shield LDAP User Guide</title>\n'
            f'<noscript><meta http-equiv="refresh" content="0; url={target}"></noscript>\n'
            f'<p>Continue to the <a id="guide" href="{target}">Shield LDAP User Guide</a>.</p>\n'
            '<script>window.location.replace(document.getElementById("guide").href + '
            'window.location.search + window.location.hash);</script>\n',
            encoding="utf-8",
        )


def build(output):
    if capture("git", "branch", "--list", "gh-pages") == "" and capture(
        "git", "branch", "--remotes", "--list", "origin/gh-pages"
    ):
        run("git", "branch", "gh-pages", "origin/gh-pages")

    run("mike", "deploy", "--title", "Development", "--allow-empty", "dev")
    published = published_versions()
    for tag in stable_tags():
        version = tag[1:]
        if version not in published:
            deploy_release(version, tag)

    published = published_versions()
    stable = [version for version in published if STABLE_VERSION.fullmatch(version)]
    version = max(stable, key=version_number, default="dev")
    if "latest" not in published[version]["aliases"]:
        run("mike", "alias", "--update-aliases", version, "latest")

    run("mike", "set-default", "latest")
    export_site(output, version)


if __name__ == "__main__":
    build(Path(sys.argv[1]))
