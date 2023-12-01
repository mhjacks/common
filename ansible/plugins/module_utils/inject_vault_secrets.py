# Copyright 2022 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Module that implements V2 of the values-secret.yaml spec
"""

import base64
import getpass
import os
import time

from ansible.module_utils.load_secrets_common import (
    find_dupes,
    get_ini_value,
    get_version,
    BaseSecretsLoader
)

default_vp_vault_policies = {
    "validatedPatternDefaultPolicy": (
        "length=20\n"
        'rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }\n'
        'rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }\n'
        'rule "charset" { charset = "0123456789" min-chars = 1 }\n'
        'rule "charset" { charset = "!@#%^&*" min-chars = 1 }\n'
    )
}


class InjectVaultSecrets(BaseSecretsLoader):
    def __init__(self, module, syaml, namespace, pod):
        self.module = module
        self.namespace = namespace
        self.pod = pod
        self.syaml = syaml

    def _get_vault_policies(self, enable_default_vp_policies=True):
        # We start off with the hard-coded default VP policy and add the user-defined ones
        if enable_default_vp_policies:
            policies = default_vp_vault_policies.copy()
        else:
            policies = {}
        policies.update(self.syaml.get("vaultPolicies", {}))
        return policies


    def validate_field(self, f):
        super().validate_field(self, f)

        vault_policy = f.get("vaultPolicy", None)
        if vault_policy is not None and vault_policy not in self._get_vault_policies():
            return (
                False,
                f"Secret has vaultPolicy set to {vault_policy} but no such policy exists",
            )

        if on_missing_value in ["generate"]:
            if value is not None:
                return (
                    False,
                    "Secret has onMissingValue set to 'generate' but has a value set",
                )
            if path is not None:
                return (
                    False,
                    "Secret has onMissingValue set to 'generate' but has a path set",
                )
            if vault_policy is None:
                return (
                    False,
                    "Secret has no vaultPolicy but onMissingValue is set to 'generate'",
                )

        return (True, "")

    def _validate_secrets(self):
        super()._validate_secrets(self)
        secrets = self._get_secrets()

        for s in secrets:
            vault_prefixes = s.get("vaultPrefixes", ["hub"])
            # This checks for the case when vaultPrefixes: is specified but empty
            if vault_prefixes is None or len(vault_prefixes) == 0:
                return (False, f"Secret {s['name']} has empty vaultPrefixes")

        return(True, "")

    def inject_vault_policies(self):
        for name, policy in self._get_vault_policies().items():
            cmd = (
                f"echo '{policy}' | oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"'cat - > /tmp/{name}.hcl';"
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c 'vault write sys/policies/password/{name} "
                f" policy=@/tmp/{name}.hcl'"
            )
            self._run_command(cmd, attempts=3)

    def sanitize_values(self):

        (ret, msg) = self._validate_secrets()
        if not ret:
            self.module.fail_json(msg)

    def _vault_secret_attr_exists(self, mount, prefix, secret_name, attribute):
        cmd = (
            f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
            f'"vault kv get -mount={mount} -field={attribute} {prefix}/{secret_name}"'
        )
        # we ignore stdout and stderr
        (ret, _, _) = self._run_command(cmd, attempts=1, checkrc=False)
        if ret == 0:
            return True

        return False

    def _inject_field(self, secret_name, f, mount, prefixes, first=False):
        on_missing_value = self._get_field_on_missing_value(f)
        override = self._get_field_override(f)
        kind = self._get_field_kind(f)
        # If we're generating the password then we just push the secret in the vault directly
        verb = "put" if first else "patch"
        b64 = self._get_field_base64(f)
        if kind in ["value", ""]:
            if on_missing_value == "generate":
                if kind == "path":
                    self.module.fail_json(
                        "You cannot have onMissingValue set to 'generate' with a path"
                    )
                vault_policy = f.get("vaultPolicy")
                gen_cmd = f"vault read -field=password sys/policies/password/{vault_policy}/generate"
                if b64:
                    gen_cmd += " | base64 --wrap=0"
                for prefix in prefixes:
                    # if the override field is False and the secret attribute exists at the prefix then we just
                    # skip, as we do not want to overwrite the existing secret
                    if not override and self._vault_secret_attr_exists(
                        mount, prefix, secret_name, f["name"]
                    ):
                        continue
                    cmd = (
                        f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                        f"\"{gen_cmd} | vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}=-\""
                    )
                    self._run_command(cmd, attempts=3)
                return

            # If we're not generating the secret inside the vault directly we either read it from the file ("error")
            # or we are prompting the user for it
            secret = self._get_secret_value(secret_name, f)
            if b64:
                secret = base64.b64encode(secret.encode()).decode("utf-8")
            for prefix in prefixes:
                cmd = (
                    f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                    f"\"vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}='{secret}'\""
                )
                self._run_command(cmd, attempts=3)

        elif kind == "path":  # path. we upload files
            # If we're generating the password then we just push the secret in the vault directly
            verb = "put" if first else "patch"
            path = self._get_file_path(secret_name, f)
            for prefix in prefixes:
                if b64:
                    b64_cmd = "| base64 --wrap=0 "
                else:
                    b64_cmd = ""
                cmd = (
                    f"cat '{path}' | oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                    f"'cat - {b64_cmd}> /tmp/vcontent'; "
                    f"oc exec -n {self.namespace} {self.pod} -i -- sh -c '"
                    f"vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}=@/tmp/vcontent; "
                    f"rm /tmp/vcontent'"
                )
                self._run_command(cmd, attempts=3)
        elif kind == "ini_file":  # ini_file. we parse an ini_file
            verb = "put" if first else "patch"
            ini_file = os.path.expanduser(f.get("ini_file"))
            ini_section = f.get("ini_section", "default")
            ini_key = f.get("ini_key")
            secret = get_ini_value(ini_file, ini_section, ini_key)
            if b64:
                secret = base64.b64encode(secret.encode()).decode("utf-8")
            for prefix in prefixes:
                cmd = (
                    f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                    f"\"vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}='{secret}'\""
                )
                self._run_command(cmd, attempts=3)

    # This assumes that self.sanitize_values() has already been called
    # so we do a lot less validation as it has already happened
    def inject_secrets(self):
        # This must come first as some passwords might depend on vault policies to exist.
        # It is a noop when no policies are defined
        self.inject_vault_policies()
        secrets = self._get_secrets()

        total_secrets = 0  # Counter for all the secrets uploaded
        for s in secrets:
            counter = 0  # This counter is to use kv put on first secret and kv patch on latter
            sname = s.get("name")
            fields = s.get("fields", [])
            mount = s.get("vaultMount", "secret")
            vault_prefixes = s.get("vaultPrefixes", ["hub"])
            for i in fields:
                self._inject_field(sname, i, mount, vault_prefixes, counter == 0)
                counter += 1
                total_secrets += 1

        return total_secrets
