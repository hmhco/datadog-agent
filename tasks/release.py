"""
Release helper tasks
"""
from __future__ import print_function

from invoke import task, Failure


@task
def update_changelog(ctx, new_version):
    """
    Quick task to generate the new CHANGELOG using reno when releasing a minor
    version (linux only).
    """
    new_version_int = map(int, new_version.split("."))

    if len(new_version_int) != 3:
        print("Error: invalid version: {}".format(new_version_int))
        raise Exit(1)

    # let's avoid loosing uncommited change with 'git reset --hard'
    try:
        ctx.run("git diff --exit-code HEAD", hide="both")
    except Failure as e:
        print("Error: You have uncommited change, please commit or stash before using update_changelog")
        return

    # let's check that the tag for the new version is present (needed by reno)
    try:
        ctx.run("git tag --list | grep {}".format(new_version))
    except Failure as e:
        print("Missing '{}' git tag: mandatory to use 'reno'".format(new_version))
        raise

    # adding the Prelude
    ctx.run("""echo 'prelude: >
    - Please refer to the `{0} tag on integrations-core <https://github.com/DataDog/integrations-core/releases/tag/{0}>`_ for the list of changes on the Core Checks.

    - Please refer to the `{0} tag on trace-agent <https://github.com/DataDog/datadog-trace-agent/releases/tag/{0}>`_ for the list of changes on the Trace Agent.

    - Please refer to the `{0} tag on process-agent <https://github.com/DataDog/datadog-process-agent/releases/tag/{0}>`_ for the list of changes on the Process Agent.'\
    | EDITOR=tee reno new prelude-release-{0} --edit""".format(new_version))

    # make sure we are up to date
    ctx.run("git fetch")

    # removing releasenotes from bugfix on the old minor.
    previous_minor = "%s.%s" % (new_version_int[0], new_version_int[1] - 1)
    ctx.run("git rm `git log {}.0...remotes/origin/{}.x --name-only \
            | grep releasenotes/notes/`".format(previous_minor, previous_minor))

    # generate the new changelog
    ctx.run("reno report \
            --ignore-cache \
            --earliest-version {}.0 \
            --version {} \
            --no-show-source > /tmp/new_changelog.rst".format(previous_minor, new_version))

    # reseting git
    ctx.run("git reset --hard HEAD")

    # remove the old header
    ctx.run("sed -i -e '1,4d' CHANGELOG.rst")

    # merging to CHANGELOG.rst
    ctx.run("cat CHANGELOG.rst >> /tmp/new_changelog.rst && mv /tmp/new_changelog.rst CHANGELOG.rst")

    # commit new CHANGELOG
    ctx.run("git add CHANGELOG.rst \
            && git commit -m \"Update CHANGELOG for {}\"".format(new_version))
