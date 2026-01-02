# Copyright (C) 2024 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

import time
from urllib.parse import urljoin

try:
    import requests

    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False

from cuckoo.common import machines
from cuckoo.common.config import cfg
from cuckoo.common.log import CuckooGlobalLogger

from .. import errors
from ..abstracts import Machinery

log = CuckooGlobalLogger(__name__)


class OrchardClient:
    def __init__(
        self,
        api_url,
        api_token,
        auth_header,
        token_prefix,
        timeout,
        verify_tls,
    ):
        self._api_url = api_url
        self._api_token = api_token
        self._auth_header = auth_header
        self._token_prefix = token_prefix
        self._timeout = timeout
        self._verify_tls = verify_tls

    def _headers(self):
        if not self._api_token or not self._auth_header:
            return {}

        if self._token_prefix:
            token = f"{self._token_prefix} {self._api_token}"
        else:
            token = self._api_token

        return {self._auth_header: token}

    def _url(self, path):
        base = self._api_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _request(self, method, path, expected_statuses, **kwargs):
        url = self._url(path)
        try:
            res = requests.request(
                method,
                url,
                headers=self._headers(),
                timeout=self._timeout,
                verify=self._verify_tls,
                **kwargs,
            )
        except requests.exceptions.RequestException as e:
            raise errors.MachineryConnectionError(
                f"Orchard API request failed: {method} {url}. {e}"
            )

        if res.status_code not in expected_statuses:
            raise errors.MachineryError(
                f"Unexpected Orchard API status {res.status_code} on "
                f"{method} {url}. Response: {res.text}"
            )

        return res

    def get_vm(self, name):
        res = self._request("get", f"/vms/{name}", (200, 404))
        if res.status_code == 404:
            return None

        try:
            return res.json()
        except ValueError as e:
            raise errors.MachineryError(
                f"Invalid JSON response from Orchard VM query. {e}"
            )

    def create_vm(self, payload):
        self._request("post", "/vms", (200, 409), json=payload)

    def update_vm(self, name, payload):
        self._request("put", f"/vms/{name}", (200,), json=payload)

    def delete_vm(self, name):
        self._request("delete", f"/vms/{name}", (200, 404))

    def get_vm_ip(self, name, wait=0):
        params = {"wait": int(wait)} if wait else {}
        res = self._request("get", f"/vms/{name}/ip", (200, 404, 503), params=params)
        if res.status_code == 404:
            raise errors.MachineNotFoundError(
                f"Orchard VM '{name}' does not exist."
            )
        if res.status_code == 503:
            return None

        try:
            payload = res.json()
        except ValueError as e:
            raise errors.MachineryError(
                f"Invalid JSON response from Orchard VM IP query. {e}"
            )

        return payload.get("ip")

    def controller_info(self):
        res = self._request("get", "/controller/info", (200,))
        try:
            return res.json()
        except ValueError:
            return {}


class Orchard(Machinery):
    name = "orchard"

    def init(self):
        self.api_url = cfg("orchard.yaml", "api_url", subpkg="machineries")
        self.api_token = cfg("orchard.yaml", "api_token", subpkg="machineries")
        self.auth_header = cfg("orchard.yaml", "auth_header", subpkg="machineries")
        self.token_prefix = cfg("orchard.yaml", "token_prefix", subpkg="machineries")
        self.timeout = cfg("orchard.yaml", "timeout", subpkg="machineries")
        self.verify_tls = cfg("orchard.yaml", "verify_tls", subpkg="machineries")
        self.ip_wait = cfg("orchard.yaml", "ip_wait", subpkg="machineries")
        self.ip_poll_interval = cfg(
            "orchard.yaml", "ip_poll_interval", subpkg="machineries"
        )
        self.stop_timeout = cfg("orchard.yaml", "stop_timeout", subpkg="machineries")
        self.stop_poll_interval = cfg(
            "orchard.yaml", "stop_poll_interval", subpkg="machineries"
        )
        self.ensure_vm = cfg("orchard.yaml", "ensure_vm", subpkg="machineries")

        self._client = OrchardClient(
            api_url=self.api_url,
            api_token=self.api_token,
            auth_header=self.auth_header,
            token_prefix=self.token_prefix,
            timeout=self.timeout,
            verify_tls=self.verify_tls,
        )
        self._machine_meta = {}

    def load_machines(self):
        super().load_machines()
        for name, values in self.cfg["machines"].items():
            ip_wait = values.get("ip_wait")
            if ip_wait is None:
                ip_wait = self.ip_wait
            ensure_vm = values.get("ensure_vm")
            if ensure_vm is None:
                ensure_vm = self.ensure_vm
            self._machine_meta[name] = {
                "vm_name": values.get("vm_name") or values["label"],
                "resources": values.get("resources") or {},
                "host_dirs": values.get("host_dirs") or [],
                "ip_wait": ip_wait,
                "ensure_vm": ensure_vm,
            }

    def restore_start(self, machine):
        state = self.state(machine)
        if state != machines.States.POWEROFF:
            raise errors.MachineUnexpectedStateError(
                f"Failed to start machine. Expected state 'poweroff'. "
                f"Actual state: {state}"
            )

        meta = self._get_meta(machine)
        vm_name = meta["vm_name"]
        existing = self._client.get_vm(vm_name)
        if existing is None:
            if not meta["ensure_vm"]:
                raise errors.MachineNotFoundError(
                    f"Orchard VM '{vm_name}' does not exist and ensure_vm=false."
                )
            payload = self._vm_payload(vm_name, meta)
            self._client.create_vm(payload)

        ip = self._wait_for_ip(vm_name, meta["ip_wait"])
        if ip:
            machine.ip = ip
            return

        raise errors.MachineryError(
            f"VM '{vm_name}' did not reach running state within "
            f"{meta['ip_wait']} seconds."
        )

    def norestore_start(self, machine):
        self.restore_start(machine)

    def stop(self, machine):
        meta = self._get_meta(machine)
        vm_name = meta["vm_name"]

        if self._client.get_vm(vm_name) is None:
            raise errors.MachineStateReachedError(
                f"Failed to stop machine. VM '{vm_name}' already removed."
            )

        self._client.delete_vm(vm_name)

        deadline = time.monotonic() + self.stop_timeout
        while True:
            if self._client.get_vm(vm_name) is None:
                return
            if time.monotonic() >= deadline:
                raise errors.MachineryError(
                    f"Timed out waiting for VM '{vm_name}' to stop."
                )
            time.sleep(self.stop_poll_interval)

    def acpi_stop(self, machine):
        self.stop(machine)

    def state(self, machine):
        meta = self._get_meta(machine)
        vm_name = meta["vm_name"]

        vm = self._client.get_vm(vm_name)
        if vm is None:
            return machines.States.POWEROFF

        try:
            ip = self._client.get_vm_ip(vm_name, wait=0)
        except errors.MachineNotFoundError:
            return machines.States.POWEROFF

        if ip:
            machine.ip = ip
            return machines.States.RUNNING

        return machines.States.STARTING

    def dump_memory(self, machine, path):
        raise NotImplementedError

    def handle_paused(self, machine):
        return

    def version(self):
        info = self._client.controller_info()
        return info.get("version", "")

    def _wait_for_ip(self, vm_name, wait_seconds):
        if wait_seconds <= 0:
            return self._client.get_vm_ip(vm_name, wait=0)

        deadline = time.monotonic() + wait_seconds
        while True:
            ip = self._client.get_vm_ip(vm_name, wait=0)
            if ip:
                return ip
            if time.monotonic() >= deadline:
                return None
            time.sleep(self.ip_poll_interval)

    def _get_meta(self, machine):
        meta = self._machine_meta.get(machine.name)
        if not meta:
            raise errors.MachineNotFoundError(
                f"Missing Orchard metadata for machine '{machine.name}'."
            )
        return meta

    def _vm_payload(self, vm_name, meta):
        payload = {"name": vm_name}
        if meta["resources"]:
            payload["resources"] = meta["resources"]
        if meta["host_dirs"]:
            payload["hostDirs"] = meta["host_dirs"]
        return payload

    @staticmethod
    def verify_dependencies():
        if not _HAVE_REQUESTS:
            raise errors.MachineryDependencyError(
                "Python package 'requests' is not installed. "
                "Install it with: pip install requests"
            )
