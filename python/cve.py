#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import json
import re
import textwrap
import webbrowser
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from shlex import split
from typing import Iterator, Tuple

import click
import requests
import ruamel.yaml
from clk.config import config
from clk.core import cache_disk
from clk.decorators import (
    flag,
    group,
    option,
)
from clk.lib import (
    call,
    check_output,
    get_secret,
    json_dumps,
)
from clk.log import get_logger

LOGGER = get_logger(__name__)


class Artifact:
    def __init__(self, digest, raw, name):
        self.raw = raw
        self.digest = digest
        self.name = name


class Report:
    def __init__(self, id, url):
        self.id = id
        self.url = url


class Alert:
    def __init__(
        self, artifact: Artifact, object, report: Report, severity, summary, raw
    ):
        self.artifact = artifact
        self.object = object
        self.report = report
        self.raw = raw
        self.severity = severity
        self.summary = summary


class AlertReporter:
    def alerts(self) -> Iterator[Alert]:
        raise NotImplementedError

    def sanity_check(self, redo_check=False):
        raise NotImplementedError


class ScoutReporter(AlertReporter):
    name = "scout"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def sanity_check(self, redo_check=False):
        try:

            @cache_disk(expire=36000)
            def _check_scout_present():
                return check_output(["docker", "scout", "-h"])

            if redo_check:
                _check_scout_present.drop()
            _check_scout_present()

        except Exception as e:
            LOGGER.error(f"docker scout binary not accessible: {e}")
            raise
        if (
            config.cve.state.get("scout", {}).get("registry", {}).get("provider")
            == "aws"
        ):
            AWSReporter().sanity_check(redo_check)

            try:

                @cache_disk(expire=36000)
                def _check_aws_ecr_accessible(profile):
                    command = ["aws"]
                    if profile:
                        command += ["--profile", profile]
                    command += ["ecr", "describe-repositories"]
                    return json.loads(check_output(command))

                if redo_check:
                    _check_aws_ecr_accessible.drop(config.cve.aws_profile)
                _check_aws_ecr_accessible(config.cve.aws_profile)
            except Exception as e:
                LOGGER.error(f"aws ecr not accessible: {e}")
                raise

    def alerts(self) -> Iterator[Alert]:
        @cache_disk(expire=12 * 3600)  # 12 hours
        def _aws_docker_login(project, profile):
            LOGGER.info(f"Configuring docker to login to aws profile {profile}")
            # password = check_output(["aws", "ecr", "get-login-password"])
            command = ["aws"]
            if profile:
                command += ["--profile", profile]
            command += ["ecr", "get-login-password"]
            password = check_output(command)
            servers = (
                config.cve.state.get("scout", {}).get("registry", {}).get("servers", [])
            )
            for server in servers:
                # login providing the password on the command line with
                # --password
                command = [
                    "docker",
                    "login",
                    server,
                    "--username",
                    "AWS",
                    "--password",
                    password,
                ]
                call(command)

        if (
            config.cve.state.get("scout", {}).get("registry", {}).get("provider")
            == "aws"
        ):
            _aws_docker_login(config.project, config.cve.aws_profile)

        # depending on whether I'm use to scan mutable tags (like :testing) or
        # immutable ones (like v1.0.1), I may want to customize the expiration
        # time
        expiration = config.cve.state.get("scout", {}).get("expiration", 3600 * 12)

        @cache_disk(expire=expiration)
        def _scout_reports(project, image):
            LOGGER.info(f"Getting scout information for {image}")
            return json.loads(check_output(f"docker scout cves {image} --format sbom"))

        @cache_disk(expire=expiration)
        def _scout_recommendations(project, image):
            LOGGER.info(f"Getting scout recommendations for {image}")
            return check_output(f"docker scout recommendations {image}")

        def _alert(artifact, alert, vulnerability, image):
            return Alert(
                artifact=Artifact(
                    digest=f"{artifact['name']}@{artifact['digest']}",
                    raw=artifact,
                    name=image,
                ),
                object={
                    "purl": alert.get("purl"),
                },
                report=Report(
                    id=vulnerability["source_id"],
                    url=vulnerability["url"],
                ),
                severity=vulnerability["cvss"]["severity"].lower(),
                summary=f"{vulnerability.get('description', 'NA')}\n# Recommendations\n{_scout_recommendations(config.project, image)}",
                raw=vulnerability,
            )

        def list_images():
            scout = config.cve.state.get("scout", {})
            if scout.get("list-images"):
                return check_output(split("clk nd list-images")).splitlines()
            else:
                return scout.get("images", [])

        def list_vulnerabilities(image):
            return _scout_reports(config.project, image).get("vulnerabilities", [])

        return [
            _alert(
                _scout_reports(config.project, image)["source"]["image"],
                alert,
                vulnerability,
                image,
            )
            for image in list_images()
            for alert in list_vulnerabilities(image)
            for vulnerability in alert.get("vulnerabilities", [])
        ]


class DependabotReporter(AlertReporter):
    name = "dependabot"

    def __init__(self, state="open", *args, **kwargs):
        self.state = state
        super().__init__(*args, **kwargs)

    def sanity_check(self, redo_check=False):
        try:

            @cache_disk(expire=36000)
            def _check_gh_present():
                return check_output(["gh", "--version"])

            if redo_check:
                _check_gh_present.drop()

            _check_gh_present()
        except Exception as e:
            LOGGER.error(f"gh binary not accessible: {e}")
            raise

    def alerts(self) -> Iterator[Alert]:
        @cache_disk(expire=36000)
        def _dependabot_alerts(project, state):
            # here {owner} and {repo} are templates interpreted by the gh tool
            return [
                alert
                for alert in json.loads(
                    check_output(
                        "gh api --paginate /repos/{owner}/{repo}/dependabot/alerts"
                    )
                )
                if state is None or alert["state"] == state
            ]

        if config.cve.refresh:
            _dependabot_alerts.drop(config.project, self.state)

        def build_artifact(alert):
            return Artifact(
                name=alert["dependency"]["manifest_path"],
                digest=alert["dependency"]["manifest_path"],
                raw=alert["dependency"]["manifest_path"],
            )

        return [
            Alert(
                summary=alert["security_advisory"]["description"],
                severity=alert["security_vulnerability"]["severity"],
                artifact=build_artifact(alert),
                object={
                    "range": alert["security_vulnerability"]["vulnerable_version_range"]
                }
                | alert["dependency"]["package"],
                report=Report(
                    id=alert["security_advisory"]["cve_id"]
                    or alert["security_advisory"]["ghsa_id"],
                    url=alert["html_url"],
                ),
                raw=alert,
            )
            for alert in _dependabot_alerts(config.project, self.state)
        ]


class ProjectDiscoveryReporter(AlertReporter):
    name = "projectdiscovery"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def sanity_check(self, redo_check=False):
        if not get_secret("PDCP_API_KEY"):
            raise ValueError(
                "No API key for projectdiscovery."
                " Please add one using"
                " 'clk secret set PDCP_API_KEY'"
            )

    def alerts(self) -> Iterator[Alert]:
        @cache_disk(expire=36000)
        def _projectdiscovery_scans(project):
            return requests.get(
                "https://api.projectdiscovery.io/v1/scans",
                headers={"X-API-Key": get_secret("PDCP_API_KEY")},
            ).json()

        if config.cve.refresh:
            _projectdiscovery_scans.drop(config.project)

        @cache_disk(expire=3600000)
        def _projectdiscovery_alerts(project, scan):
            return [
                alert
                for alert in requests.get(
                    f"https://api.projectdiscovery.io/v1/scans/{scan}/export",
                    headers={"X-API-Key": get_secret("apikey@projectdiscovery")},
                ).json()
            ]

        def build_artifact(alert):
            return Artifact(
                name=alert["host"],
                digest=alert["host"],
                raw=alert["host"],
            )

        def build_alert(alert):
            return Alert(
                summary=alert["description"],
                severity=alert["severity"],
                artifact=build_artifact(alert),
                object={
                    "tags": alert.get("tags"),
                },
                report=Report(
                    id=alert["template_id"],
                    url=alert.get("template_url", alert.get("reference", [None])[0]),
                ),
                raw=alert,
            )

        scan = _projectdiscovery_scans(config.project)["data"][0]
        scan = scan["scan_id"]
        if config.cve.refresh:
            _projectdiscovery_alerts.drop(config.project, scan)

        yield from [
            build_alert(alert)
            for alert in _projectdiscovery_alerts(config.project, scan)
        ]


class AWSReporter(AlertReporter):
    name = "aws"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def sanity_check(self, redo_check=False):
        try:

            @cache_disk(expire=36000)
            def _check_aws_present():
                return check_output(["aws", "--version"])

            if redo_check:
                _check_aws_present.drop()

            _check_aws_present()

        except Exception as e:
            LOGGER.error(f"aws binary not accessible: {e}")
            raise

        try:

            @cache_disk(expire=36000)
            def _check_aws_ecr_accessible(profile):
                command = ["aws"]
                if profile:
                    command += ["--profile", profile]
                command += ["ecr", "describe-repositories"]
                return json.loads(check_output(command))

            if redo_check:
                _check_aws_ecr_accessible.drop(config.cve.aws_profile)
            _check_aws_ecr_accessible(config.cve.aws_profile)
        except Exception as e:
            LOGGER.error(f"aws ecr not accessible: {e}")
            raise

    @property
    def _artifacts(self):
        @cache_disk(expire=36000)
        def _aws_list_repositories(profile):
            LOGGER.info(f"Getting the list of repositories for profile {profile}")
            command = ["aws"]
            if profile:
                command += ["--profile", profile]
            command += ["ecr", "describe-repositories"]
            return json.loads(check_output(command))

        @cache_disk(expire=36000)
        def _aws_list_images(profile, repository):
            LOGGER.info(f"Getting images of {repository} for profile {profile}")
            command = ["aws"]
            if profile:
                command += ["--profile", profile]
            command += ["ecr", "list-images", "--repository-name", repository]
            return json.loads(check_output(command))

        result = sum(
            [
                [
                    {
                        "repository_name": repository["repositoryName"],
                        "image_ids": image_ids,
                    }
                    for image_ids in _aws_list_images(
                        config.cve.aws_profile, repository["repositoryName"]
                    )["imageIds"]
                ]
                for repository in _aws_list_repositories(config.cve.aws_profile)[
                    "repositories"
                ]
                if not config.cve.aws_image_names
                or repository["repositoryName"] in config.cve.aws_image_names
            ],
            [],
        )
        result = [
            artifact
            for artifact in result
            if (
                not config.cve.aws_filter_image_tag
                or artifact["image_ids"].get("imageTag")
                == config.cve.aws_filter_image_tag
            )
            and (
                not config.cve.aws_image_names
                or artifact["repository_name"] in config.cve.aws_image_names
            )
        ]
        return result

    def alerts(self) -> Iterator[Alert]:
        @cache_disk(expire=36000)
        def _list_cve(profile, repository, image_id):
            LOGGER.info(
                f"Listing cve of {image_id} for {repository} for profile {profile}"
            )
            return json.loads(
                check_output(
                    split(
                        f"aws --profile '{profile}'"
                        " ecr describe-image-scan-findings"
                        f" --repository-name '{repository}'"
                        f" --image-id {image_id}"
                    )
                )
            )

        for artifact in self._artifacts:
            image_id = [
                f"{key}={value}" for key, value in artifact["image_ids"].items()
            ][0]
            if config.cve.refresh:
                _list_cve.drop(
                    config.cve.aws_profile, artifact["repository_name"], image_id
                )
            cve = _list_cve(
                config.cve.aws_profile,
                artifact["repository_name"],
                image_id,
            )["imageScanFindings"]["findings"]
            for cve in cve:
                yield Alert(
                    summary=textwrap.fill(cve["description"], 80),
                    severity=cve["severity"].lower(),
                    artifact=Artifact(
                        name=f"{artifact['repository_name']}:{artifact['image_ids'].get('imageTag', artifact['image_ids']['imageDigest'])}",
                        raw=artifact,
                        digest=f"{artifact['repository_name']}:{artifact['image_ids']['imageDigest']}",
                    ),
                    object={
                        attribute["key"]: attribute["value"]
                        for attribute in cve["attributes"]
                        if attribute["key"] in ("package_name", "package_version")
                    },
                    report=Report(url=cve["uri"], id=cve["name"]),
                    raw=cve,
                )


yaml = ruamel.yaml.YAML()
yaml.default_flow_style = False

reporters = [
    AWSReporter(),
    DependabotReporter(),
    ProjectDiscoveryReporter(),
    ScoutReporter(),
]


class CVEConfig:
    def __init__(self):
        self._reporters = reporters
        self.reporter = [reporter.name for reporter in self._reporters]
        self._aws_profile = None
        self._state = {"version": "0.0.1"}

    @property
    def aws_profile(self):
        if not self._aws_profile:
            self._aws_profile = self.state.get("aws", {}).get("profile")
        return self._aws_profile

    @aws_profile.setter
    def aws_profile(self, profile):
        self._aws_profile = profile

    def walk(self) -> Iterator[Tuple[AlertReporter, Alert]]:
        for reporter in self.reporters:
            for alert in reporter.alerts():
                if not self.is_dismissed_by_command_line(reporter, alert) and (
                    self.ignore_config_filters
                    or not self.is_dismissed_by_config(reporter, alert)
                ):
                    yield reporter, alert
                    self.limit -= 1
                    if self.limit <= 0:
                        break

    def sanity_checks(self, redo_checks=False):
        for reporter in self.reporters:
            reporter.sanity_check(redo_checks)

    @property
    def aws_filter_image_tag(self):
        return self.state.get("aws", {}).get("filter-image-tag", None)

    @property
    def aws_image_names(self):
        return self.state.get("aws", {}).get("image-names", [])

    def check_valid_until(self, d):
        if "valid_until" in d:
            return datetime.now() <= datetime.strptime(
                d["valid_until"], "%Y-%m-%d %H:%M:%S"
            )
        else:
            return True

    def is_dismissed_by_command_line(self, reporter, alert):
        if self.report_id and alert.report.id not in self.report_id:
            return True
        if self.artifact_digest and alert.artifact.digest not in self.artifact_digest:
            return True
        if self.artifact_name and alert.artifact.name not in self.artifact_name:
            return True
        if self.severity and alert.severity not in self.severity:
            return True
        if self.not_severity and alert.severity in self.not_severity:
            return True

    def is_dismissed_by_config(self, reporter, alert):
        if f"{alert.artifact.name}-{alert.report.id}" in config.cve.state.get(
            "dismissed-artifact-names-report", []
        ):
            return True
        if alert.severity in config.cve.state.get("dismissed-severities", []):
            return True
        if alert.artifact.digest in config.cve.state.get("dismissed-artifacts", []):
            return True
        if alert.artifact.name in config.cve.state.get("dismissed-artifact-names", []):
            return True
        if alert.severity in config.cve.state.get("dismissed-severities", []):
            return True
        report_dismissal = config.cve.state.get("dismissed-reports", {}).get(
            alert.report.id, None
        )
        if report_dismissal is None:
            return False
        else:
            return self.check_valid_until(report_dismissal)

    @property
    def reporter(self):
        return self._reporter

    @reporter.setter
    def reporter(self, reporter_names):
        reporter_names = reporter_names or self.state.get("reporters", [])
        self.reporters = [
            reporter for reporter in self._reporters if reporter.name in reporter_names
        ]

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, path):
        self._path = path
        if self._path is None:
            return
        if self._path.exists():
            self._state = yaml.load(self._path)
        else:
            LOGGER.info(
                "First time using clk cve?"
                f" Please edit the file at {self._path} to configure it"
            )
            self.save()

    @property
    def state(self):
        return self._state

    def save(self):
        yaml.dump(self._state, self.path)


@group()
@option(
    "--path",
    default=(Path(config.project) / "cve.yaml") if config.project else None,
    expose_class=CVEConfig,
    type=Path,
    required=True,
    help="Where the config file resides",
)
@option(
    "--reporter",
    type=click.Choice([reporter.name for reporter in reporters]),
    expose_class=CVEConfig,
    multiple=True,
    help="What reporter to enable",
)
@flag("--ignore-config-filters", expose_class=CVEConfig, help="Show all the alerts")
@flag("--refresh", expose_class=CVEConfig, help="Don't rely of the cache")
@option(
    "--aws-profile",
    expose_class=CVEConfig,
    help="Speed up processing",
)
@option(
    "--severity",
    multiple=True,
    type=click.Choice(
        ["undefined", "low", "medium", "moderate", "high", "critical"],
    ),
    expose_class=CVEConfig,
    help="Focus on those kind of alerts",
)
@option(
    "--not-severity",
    multiple=True,
    type=click.Choice(
        ["undefined", "low", "medium", "moderate", "high", "critical"],
    ),
    expose_class=CVEConfig,
    help="Ignore those kinds of alerts",
)
@option(
    "--report-id",
    help="Focus on alerts from that report only",
    expose_class=CVEConfig,
    multiple=True,
)
@option(
    "--artifact-digest",
    help="Focus on alerts from that artifact only",
    expose_class=CVEConfig,
    multiple=True,
)
@option(
    "--artifact-name",
    help="Focus on alerts from that artifact only",
    expose_class=CVEConfig,
    multiple=True,
)
@option(
    "--limit",
    help="Show only that number",
    default=9999,
    type=int,
    expose_class=CVEConfig,
)
@flag("--redo-checks", help="Try again running the sanity checks")
def cve(redo_checks):
    """Deal with cve alerts."""
    cve: CVEConfig = config.cve
    cve.sanity_checks(redo_checks)


@cve.command()
def ipython():
    """No comment."""
    import IPython

    IPython.start_ipython(argv=[], user_ns=(globals() | locals()))


@cve.command()
@option("--limit", help="Show only that number", default=1, type=int)
def _open(limit):
    """Browse the url of the matching alerts."""
    cve: CVEConfig = config.cve
    cve.limit = limit
    for reporter, alert in cve.walk():
        LOGGER.info(
            f"{reporter.name}: {alert.report.id} found in {alert.artifact.name}"
        )
        webbrowser.open(alert.report.url)


@cve.command()
@flag("--show-reports", help="Also show the reports")
def stats(show_reports):
    """Get a 100 feet view of the alerts."""
    reports = defaultdict(int)
    severity = defaultdict(int)
    artifacts = defaultdict(int)
    cve: CVEConfig = config.cve
    for reporter, alert in cve.walk():
        reports[alert.report.id] += 1
        artifacts[f"{reporter.name}: {alert.artifact.digest}"] += 1
        severity[f"{alert.severity}"] += 1

    if show_reports:
        print(f"reports ({len(reports)})")
        print(json_dumps(reports))

    print(f"artifacts ({len(artifacts)})")
    print(json_dumps(artifacts))
    print(f"severity ({len(severity)})")
    print(json_dumps(severity))


@cve.command()
@flag("--export-org", help="Export in org format")
@option(
    "--limit",
    default=20,
    help="Don't dump too many to avoid slowing org too much",
)
@flag(
    "--short",
    help="Write less stuff",
)
@flag(
    "--shorter",
    help="Write the bare minimum",
)
def show(export_org, limit, short, shorter):
    """Dump those in reports useful for taking further actions."""
    short = short or shorter
    indent = 2
    if export_org:
        print(f"{indent * '*'} report")
    for reporter, alert in config.cve.walk():
        limit = limit - 1
        if limit < 0:
            return
        data = {
            "reporter": reporter.__class__.__name__,
            "artifact": alert.artifact.raw,
            "report_id": alert.report.id,
            "alert": alert.raw,
            "summary": alert.summary,
        }
        if export_org:
            print(
                f"{'*' * (indent + 1)} [{alert.severity}] [[{alert.report.url}][{alert.report.id}]] {alert.artifact.digest}"
            )
            for key, value in alert.object.items():
                print(textwrap.indent(f"- {key} :: {value}", " " * (indent + 2)))
            if short and not shorter:
                summary = textwrap.indent(
                    textwrap.fill(textwrap.shorten(alert.summary, 300)),
                    " " * (indent + 2),
                )
                print(textwrap.indent(f"summary:\n{summary}", " " * (indent + 1)))

            if not short:
                print(f"{'*' * (indent + 2)} summary")
                print(
                    f"""\
#+BEGIN_SRC markdown :results verbatim :exports both
{re.sub(r"^\*", ",*", alert.summary, flags=re.MULTILINE)}
#+END_SRC""",
                )
                print(f"{'*' * (indent + 2)} raw")
                print(
                    f"""\
#+NAME: {alert.report.id}
#+BEGIN_SRC js :results verbatim :exports both
{json_dumps(alert.raw)}
#+END_SRC""",
                )
        else:
            print(json_dumps(data))


@cve.command()
@flag("--refresh", help="Don't use the cache")
def doctor(refresh):
    """Check for some incoherence."""
    cve: CVEConfig = config.cve
    LOGGER.debug(
        "Force ignore filters and use ALL reporters or the doctor will say wrong results"
    )
    config.cve.ignore_config_filters = True

    current_reports = set(alert.report.id for _, alert in cve.walk())
    dismissed_reports = set()
    github_issues_to_reports = defaultdict(set)

    for dismissed_report, data in cve.state.get("dismissed-reports", {}).items():
        dismissed_reports.add(dismissed_report)
        if github_issue := data.get("github_issue"):
            github_issues_to_reports[github_issue].add(dismissed_report)

    @cache_disk(expire=3600)
    def _github_issue_closed(issue):
        return check_output(
            split(f"gh issue view {issue} --json closed --jq .closed")
        ).strip()

    for github_issue, associated_reports in github_issues_to_reports.items():
        if refresh:
            _github_issue_closed.drop(github_issue)
        if _github_issue_closed(github_issue) == "true":
            print(f"github {github_issue} was closed", end=", ")
            if still_ongoing_reports := associated_reports.intersection(
                current_reports
            ):
                print(
                    "but those reports are still relevant: {}".format(
                        ", ".join(still_ongoing_reports)
                    )
                )
            else:
                print("maybe time to close it?")

    if len(dismissed_reports - current_reports) > 0:
        print("Those reports are not relevant anymore")
    for id in dismissed_reports - current_reports:
        print(id)
