#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# <xbar.title>Gitlab CI Pipeline Status</xbar.title>
# <xbar.desc>Shows currently running pipelines from your GitLab.</xbar.desc>
# <xbar.version>v0.1</xbar.version>
# <xbar.author>Raj Perera</xbar.author>
# <xbar.author.github>rajiteh</xbar.author.github>
# <xbar.dependencies>python</xbar.dependencies>
# <xbar.image>https://raw.githubusercontent.com/pionl/bitbar-gitlab-ci/master/gitlab_ci.png</xbar.image>

from pathlib import Path
import os
import sys
import logging
import requests
from datetime import datetime
import subprocess
from shlex import quote
from typing import Any

# Dependency management function
def install(pkg: str, spec: str = "", cache_dir: Path | str = "~/.cache"):
    import pip
    import importlib.metadata
    from pip._vendor.packaging.requirements import Requirement
    name, cache = Path(__file__), Path(os.environ.get("XDG_CACHE_HOME", cache_dir))
    sitep = (cache / f"pyxbar/{name.name}/site-packages").expanduser().as_posix()
    sys.path.append(sitep) if sitep not in sys.path else None
    try:
        requirement = Requirement(spec or pkg)
        assert importlib.metadata.version(requirement.name) in requirement.specifier
    except Exception:
        pip.main(["install", "--upgrade", f"--target={sitep}", *(spec or pkg).split()])
        importlib.invalidate_caches()

install("pyxbar")

from pyxbar import Config, Divider, Menu, MenuItem, ShellItem

# Logger setup
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="=====> %(message)s")

# Configuration class
from dataclasses import dataclass, field

@dataclass
class PluginConfig(Config):
    URLS_TO_WATCH: list[str] = field(default_factory=list, repr=False)
    GITLAB_API_URL: str = ""
    GITLAB_TOKEN: str = ""
    GITLAB_TOKEN_MODE: str = "config"
    GITLAB_TOKEN_ENV_VAR: str = "GITLAB_CI_TOKEN"
    GITLAB_TOKEN_KEYCHAIN: str = "gitlab-ci-token"
    GITLAB_TOKEN_ONEPASSWORD: str = "op://vault/secret/field"
    _cached_gitlab_token: str = ""
    def add_url(self, url: str):
        url = url.strip().split("#")[0].split("?")[0]
        if not url.startswith("http"):
            raise ValueError(f"Invalid URL: {url}")
        self.URLS_TO_WATCH.append(url)
        self.save()

    def remove_url(self, url: str):
        self.URLS_TO_WATCH.remove(url)
        self.save()

    def remove_all(self):
        self.URLS_TO_WATCH = []
        self.save()

    def save(self):
        self.URLS_TO_WATCH = list(set(self.URLS_TO_WATCH))
        super().save()

    def as_config_dict(self) -> dict[str, Any]:
        sanitize = lambda x: x if isinstance(x, (str, int, float, bool, list, tuple, dict)) else str(x)
        return {
            f"{self.prefix}{k}": sanitize(getattr(self, k)) for k in self.config_fields()
        }
    
    def get_gitlab_token(self):
        if self._cached_gitlab_token:
            return self._cached_gitlab_token
        
        token = ""
        if self.GITLAB_TOKEN_MODE == "config":
            token = self.GITLAB_TOKEN
        if self.GITLAB_TOKEN_MODE == "env":
            token = os.environ.get(self.GITLAB_TOKEN_ENV_VAR)
        elif self.GITLAB_TOKEN_MODE == "onepassword":
            token = subprocess.check_output(['op', 'read', self.GITLAB_TOKEN_ONEPASSWORD]).decode().strip()
        elif self.GITLAB_TOKEN_MODE == "keychain":        
            token = subprocess.check_output(['security', 'find-generic-password', '-a', self.GITLAB_TOKEN_KEYCHAIN, '-w']).decode().strip()
        
        if not token:
            raise ValueError(f"Invalid token mode: {self.GITLAB_TOKEN_MODE}")

        self._cached_gitlab_token = token
        return token
        


# GitLab CI Pipeline Status Checker
class GitLabCIChecker:
    def __init__(self, gitlab_host, token, url):
        self.gitlab_host = gitlab_host
        self.token = token
        self.headers = {'PRIVATE-TOKEN': token}
        self.url = url
        self.project_id, self.project_slug, self.ref_type, self.ref = self.parse_url(url)
        pipeline = self.get_pipeline()
        self.pipeline_id = pipeline['id']
        self.status = pipeline['status']

    def get_project_id(self, project_slug):
        endpoint = f"{self.gitlab_host}/api/v4/projects/{requests.utils.quote(project_slug, safe='')}"
        response = requests.get(endpoint, headers=self.headers)
        response.raise_for_status()
        return response.json()['id']

    def parse_url(self, url):
        parts = url.replace(self.gitlab_host, '').strip('/').split('/')
        if 'merge_requests' in parts:
            ref_index = parts.index('merge_requests')
            ref_type = 'merge_requests'
        elif 'tree' in parts:
            ref_index = parts.index('tree')
            ref_type = 'branch'
        elif 'tags' in parts:
            ref_index = parts.index('tags')
            ref_type = 'tag'
        elif 'pipelines' in parts:
            ref_index = parts.index('pipelines')
            ref_type = 'pipeline'
        else:
            raise ValueError("URL format not recognized")
        
        ref = parts[ref_index + 1]
        project_slug = '/'.join(parts[:ref_index-1])
        project_id = self.get_project_id(project_slug)
        return project_id, project_slug, ref_type, ref

    def get_pipeline(self):
            endpoint = f"{self.gitlab_host}/api/v4/projects/{self.project_id}"
            
            if self.ref_type == 'merge_requests':
                endpoint += f"/merge_requests/{self.ref}/pipelines"
            elif self.ref_type == 'pipeline':
                endpoint += f"/pipelines/{self.ref}"
            else:
                endpoint += f"/pipelines?ref={self.ref}&order_by=updated_at&sort=desc"
            
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            if self.ref_type == "merge_requests":
                # For merge requests, directly get the latest pipeline
                resp = response.json()
                # check if its a list
                if isinstance(resp, list):
                    latest_pipeline = resp[0]
                else:
                    latest_pipeline = resp['pipeline']  # Assuming the latest pipeline is the first
            elif self.ref_type == "pipeline":
                latest_pipeline = response.json()
            else:
                # For branches and tags, the latest pipeline info is under the "commit" key
                latest_pipeline = response.json()[0]

            return latest_pipeline

    def retry_pipeline(self):
        endpoint = f"{self.gitlab_host}/api/v4/projects/{self.project_id}/pipelines/{self.pipeline_id}/retry"
        response = requests.post(endpoint, headers=self.headers)
        response.raise_for_status()

# Script commands and menu items
class ScriptCommand(MenuItem):
    def __init__(self, title, command, *params):
        script_path = os.path.abspath(__file__)
        python_interpreter_path = sys.executable
        quoted_params = map(quote, (python_interpreter_path, script_path, command, *params))
        super().__init__(title=title, shell=" ".join(quoted_params), refresh=True)

ICONS = {
    "success": "✅",
    "failed": "❌",
    "running": "🏃",
    "pending": "⏳",
    "skipped": "⏭️",
    "canceled": "🚫",
}

# Menu item class for displaying pipeline status
class GitlabStatus(MenuItem):
    def __init__(self, url, gitlab_api, gitlab_token):
        self.checker = GitLabCIChecker(gitlab_api, gitlab_token, url)
        status_icon = ICONS.get(self.checker.status, "")
        super().__init__(title=f"{status_icon} ({self.checker.status.upper()}) {self.checker.project_slug} {self.checker.ref_type}#{self.checker.ref}", href=self.checker.url)
        self.with_submenu(ScriptCommand("🗑️ Clear", "remove_url", self.checker.url))
        if self.checker.status == "failed":
            self.with_submenu(ScriptCommand("🔁 Retry", "retry_pipeline", self.checker.url))

# Main function to generate xbar menu
def xbar_menu(config: PluginConfig):
    try:
        jobs = [GitlabStatus(url, config.GITLAB_API_URL, config.get_gitlab_token()) for url in config.URLS_TO_WATCH]
    except Exception as e:
        Menu(f"🚦❔").with_items(MenuItem(f"🚫 {str(e)}")).print()
        return
    
    statistics = {status: len([job for job in jobs if job.checker.status == status]) for status in ICONS.keys()}
    title_stats = ' '.join(f"{count}{ICONS[status]}" for status, count in statistics.items() if count > 0)
    Menu(f"🚦 {title_stats}").with_items(
        *jobs,
        MenuItem(f"Refreshed at {datetime.now().strftime('%H:%M:%S')}"),
        Divider(),
        ScriptCommand("➕ Add URL", "add_url"),
        ScriptCommand("🚮 Remove All", "remove_all"),
        ScriptCommand("✅ Remove Success", "remove_success"),
        Divider(),
        config, # Debug config
    ).print()

def prompt_user(msg):
    cmd = f'''
tell me
	activate
	text returned of (display dialog "{msg}" default answer "")
end tell'''
    return subprocess.check_output(['osascript', '-e', cmd]).decode().strip()

def display_message(msg):
    subprocess.run(['osascript', '-e', f'display dialog "{msg}" buttons {{"OK"}}'])

if __name__ == "__main__":

    config = PluginConfig.get_config()
    if len(sys.argv) < 2:
        xbar_menu(config)
    elif sys.argv[1] == "add_url":
        result = prompt_user("Enter the GitLab URL")
        try:
            config.add_url(result)
        except Exception as e:
            display_message(str(e))
    elif sys.argv[1] == "remove_url":
        config.remove_url(sys.argv[2])
    elif sys.argv[1] == "remove_all":
        config.remove_all()
    elif sys.argv[1] == "remove_success":
        urls = [url for url in config.URLS_TO_WATCH if GitLabCIChecker(config.GITLAB_API_URL, config.get_gitlab_token(), url).status == "success"]
        for url in urls:
            config.remove_url(url)
    elif sys.argv[1] == "retry_pipeline":
        try:
            checker = GitLabCIChecker(config.GITLAB_API_URL, config.get_gitlab_token(), sys.argv[2])
            checker.retry_pipeline()
        except Exception as e:
            display_message(str(e))
            sys.exit(1)
    else:
        display_message(f"Unknown command: {sys.argv[1]}")
        sys.exit(1)
