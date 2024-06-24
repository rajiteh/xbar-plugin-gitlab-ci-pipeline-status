#!/opt/homebrew/bin/python3
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
from typing import Any, Union, Tuple

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
class WatchConfig(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)

    @property
    def notify(self) -> bool:
        return self.get("notify", False)
    
    @notify.setter
    def notify(self, value: bool):
        self["notify"] = value

    @property
    def last_notified_at(self) -> Union[Tuple[datetime, str], None]:
        value = self.get("last_notified_at")
        if value:
            timestamp, state = value.split("|")
            return datetime.strptime(timestamp, '%H:%M:%S'), state
        return None
    
    @last_notified_at.setter
    def last_notified_at(self, value: Tuple[datetime, str]):
        timestamp, state = value
        self["last_notified_at"] = f"{timestamp.strftime('%H:%M:%S')}|{state}"

    def send_notification(self, title, state: str):
        if self.last_notified_at: # Make sure we have a last notified time
            _, last_state = self.last_notified_at
            if last_state != state:
                display_notification(title, f"Pipeline state changed from '{last_state}' to '{state}'")
            
        self.last_notified_at = (datetime.now(), state)

    @property
    def show_jobs(self) -> bool:
        return self.get("show_jobs", False)
    
    @show_jobs.setter
    def show_jobs(self, value: bool):
        self["show_jobs"] = value

@dataclass
class PluginConfig(Config):
    URLS_TO_WATCH: dict[str,WatchConfig] = field(default_factory=dict, repr=False)
    NOTIFY_DEFAULT: bool = True
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
        if url in self.URLS_TO_WATCH.keys():
            return
        
        self.URLS_TO_WATCH[url] = WatchConfig(notify=self.NOTIFY_DEFAULT, show_jobs=False)
        self.save()

    def remove_url(self, url: str):
        if url in self.URLS_TO_WATCH.keys():
            del self.URLS_TO_WATCH[url]
            self.save()

    def remove_all(self):
        self.URLS_TO_WATCH = {}
        self.save()

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

    def get_watch_config(self, url) -> WatchConfig:
        return WatchConfig(**self.URLS_TO_WATCH[url])
    
    def set_watch_config(self, url, config):
        self.URLS_TO_WATCH[url] = config
        self.save()

    @property
    def urls(self) -> dict[str,WatchConfig]:
        return {url: WatchConfig(**config) for url, config in self.URLS_TO_WATCH.items()}

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

    def get_jobs(self) -> dict[str, list]:
        endpoint = f"{self.gitlab_host}/api/v4/projects/{self.project_id}/pipelines/{self.pipeline_id}/jobs"
        response = requests.get(endpoint, headers=self.headers)
        response.raise_for_status()
        jobs = response.json()
        # group by stage
        stages = {}
        for job in jobs:
            stage = job['stage']
            if stage not in stages:
                stages[stage] = []
            stages[stage].append(job)
        # reverse the keys in stages
        stages = dict(reversed(list(stages.items())))
        return stages
    
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
    "manual": "🤖",
}

# Menu item class for displaying pipeline status
class GitlabStatus(MenuItem):
    def __init__(self, url, watch_config: WatchConfig, gitlab_api, gitlab_token):
        self.checker = GitLabCIChecker(gitlab_api, gitlab_token, url)
        status_icon = ICONS.get(self.checker.status, "")
        title = f"{status_icon} ({self.checker.status.upper()}) {self.checker.project_slug} {self.checker.ref_type}#{self.checker.ref}"
        super().__init__(title=title, href=self.checker.url)
        if watch_config.show_jobs:
            jobs = self.checker.get_jobs()
            for stage, jobs in jobs.items():
                stage_menu = MenuItem(stage)
                for job in jobs:
                    job_icon = ICONS.get(job['status'], "")
                    job_title = f"{job_icon} {job['name']}"
                    stage_menu.with_submenu(MenuItem(job_title, href=job['web_url']))
                self.with_submenu(stage_menu)
            self.with_submenu(Divider())
            self.with_submenu(ScriptCommand("🙈 Hide Jobs", "hide_jobs", self.checker.url))
        else:
            self.with_submenu(ScriptCommand("🫣 Show Jobs", "show_jobs", self.checker.url))
        if watch_config.notify:
            self.with_submenu(ScriptCommand("🔕 Disable Notifications", "disable_notify", self.checker.url))
        else:
            self.with_submenu(ScriptCommand("🔔 Enable Notifications", "enable_notify", self.checker.url))
        if self.checker.status == "failed":
            self.with_submenu(ScriptCommand("🔁 Retry", "retry_pipeline", self.checker.url))
        self.with_submenu(ScriptCommand("🗑️ Clear", "remove_url", self.checker.url))
    
# Main function to generate xbar menu
def xbar_menu(config: PluginConfig):
    try:
        jobs = []
        for url, watch_config in config.urls.items():
            job = GitlabStatus(url, watch_config, config.GITLAB_API_URL, config.get_gitlab_token())
            if watch_config.notify:
                watch_config.send_notification(job.title, job.checker.status)
                config.set_watch_config(url, watch_config)
            jobs.append(job)
    except Exception as e:
        Menu(f"🚦❔").with_items(MenuItem(f"🚫 {str(e)}")).print()
        logger.error(e, exc_info=True)
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

def display_notification(title, msg):
    logger.info(f"Displaying notification: {title} - {msg}")
    subprocess.run(['osascript', '-e', f'display notification "{msg}" with title "{title}" sound name "Blow"'])
    
if __name__ == "__main__":

    config = PluginConfig.get_config()
    
    if len(sys.argv) < 2:
        xbar_menu(config)
        sys.exit(0)
    
    cmd = sys.argv[1]
    if cmd == "add_url":
        result = prompt_user("Enter the GitLab URL")
        try:
            config.add_url(result)
        except Exception as e:
            display_message(str(e))

    url = sys.argv[2]
    if cmd == "remove_url":
        config.remove_url(url)
    elif cmd == "remove_all":
        config.remove_all()
    elif cmd == "remove_success":
        urls = [url for url in config.urls if GitLabCIChecker(config.GITLAB_API_URL, config.get_gitlab_token(), url).status == "success"]
        for url in urls:
            config.remove_url(url)
    elif cmd == "retry_pipeline":
        try:
            checker = GitLabCIChecker(config.GITLAB_API_URL, config.get_gitlab_token(), url)
            checker.retry_pipeline()
        except Exception as e:
            display_message(str(e))
            sys.exit(1)
    elif cmd == "enable_notify":
        watch_config = config.get_watch_config(url)
        watch_config.notify = True
        config.set_watch_config(url, watch_config)
    elif cmd == "disable_notify":
        watch_config = config.get_watch_config(url)
        watch_config.notify = False
        config.set_watch_config(url, watch_config)
    elif cmd == "show_jobs":
        watch_config = config.get_watch_config(url)
        watch_config.show_jobs = True
        config.set_watch_config(url, watch_config)
    elif cmd == "hide_jobs":
        watch_config = config.get_watch_config(url)
        watch_config.show_jobs = False
        config.set_watch_config(url, watch_config)
    else:
        display_message(f"Unknown command: {cmd}")
        sys.exit(1)
