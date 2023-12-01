# Copyright 2022, 2023 Red Hat, Inc.
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
Module that implements some common functions
"""

import configparser
from collections.abc import MutableMapping

import os.path


def find_dupes(array):
    """
    Returns duplicate items in a list

    Parameters:
        l(list): Array to check for duplicate entries

    Returns:
        dupes(list): Array containing all the duplicates and [] is there are none
    """
    seen = set()
    dupes = []
    for x in array:
        if x in seen:
            dupes.append(x)
        else:
            seen.add(x)
    return dupes


def get_version(syaml):
    """
    Return the version: of the parsed yaml object. If it does not exist
    return 1.0

    Returns:
        ret(str): The version value in of the top-level 'version:' key
    """
    return str(syaml.get("version", "1.0"))


def flatten(dictionary, parent_key=False, separator="."):
    """
    Turn a nested dictionary into a flattened dictionary and also
    drop any key that has 'None' as their value

    Parameters:
        dictionary(dict): The dictionary to flatten

        parent_key(str): The string to prepend to dictionary's keys

        separator(str): The string used to separate flattened keys

    Returns:

        dictionary: A flattened dictionary where the keys represent the
        path to reach the leaves
    """

    items = []
    for key, value in dictionary.items():
        new_key = str(parent_key) + separator + key if parent_key else key
        if isinstance(value, MutableMapping):
            items.extend(flatten(value, new_key, separator).items())
        elif isinstance(value, list):
            for k, v in enumerate(value):
                items.extend(flatten({str(k): v}, new_key).items())
        else:
            if value is not None:
                items.append((new_key, value))
    return dict(items)


def get_ini_value(inifile, inisection, inikey):
    """
    Return a value from an ini-file or 'None' if it does not exist

    Parameters:
        inifile(str): The path to the ini-file

        inisection(str): The section in the ini-file to look for the key

        inikey(str): The key to look up inside the ini-file's section

    Returns:

        obj: The value of the key or None if it does not exist
    """
    config = configparser.ConfigParser()
    config.read(inifile)
    return config.get(inisection, inikey, fallback=None)

def expand_path_value(p):
    """
    Expand a given filename, using both os.path.expandvars and os.path.expanduser

    Parameters:
        p(str): A pathname to be expanded

    Returns:
        obj: The expanded pathname
    """
    return os.path.expanduser(os.path.expandvars(p))

def get_path_contents(p):
    """
    Return the contents of the path p

    Parameters:
        p(str): A pathname to retrieve the contents of.

    Returns:
        obj: The contents of the file as bytes. No attempt is made to decode the file.
    """

    with open(expand_path_value(p), 'rb') as f:
        return f.read()

def stringify_dict(d):
    """
    Return a copy of d mutated such that each element has been coerced to string.
    This is to ensure that the object can be safely applied as labels or annotations
    to a kubernetes secret object.

    Parameters:
        d(dict): The dict to coerce

    Returns:

        dict: The new dictionary, whose keys and values are all guaranteed to be strings
    """
    stringified_dict = {}

    for (k, v) in d.items():
        stringified_dict[str(k)] = str(v)

    return stringified_dict

class BaseSecretsV3Loader:
    def __init__(self, module, syaml, namespace, pod):
        self.module = module
        self.namespace = namespace
        self.pod = pod
        self.syaml = syaml

    def _run_command(self, command, attempts=1, sleep=3, checkrc=True):
        """
        Runs a command on the host ansible is running on. A failing command
        will raise an exception in this function directly (due to check=True)

        Parameters:
            command(str): The command to be run.
            attempts(int): Number of times to retry in case of Error (defaults to 1)
            sleep(int): Number of seconds to wait in between retry attempts (defaults to 3s)

        Returns:
            ret(subprocess.CompletedProcess): The return value from run()
        """
        for attempt in range(attempts):
            ret = self.module.run_command(
                command,
                check_rc=checkrc,
                use_unsafe_shell=True,
                environ_update=os.environ.copy(),
            )
            if ret[0] == 0:
                return ret
            if attempt >= attempts - 1:
                return ret
            time.sleep(sleep)

    def _get_backingstore(self):
        """
        Return the backingStore: of the parsed yaml object. If it does not exist
        return 'vault'

        Returns:
            ret(str): The value of the top-level 'backingStore:' key
        """
        return str(self.syaml.get("backingStore", "vault"))

    def _get_secrets(self):
        return self.syaml.get("secrets", {})

    def _get_field_on_missing_value(self, f):
        # By default if 'onMissingValue' is missing we assume we need to
        # error out whenever the value is missing
        return f.get("onMissingValue", "error")

    def _get_field_value(self, f):
        return f.get("value", None)

    def _get_field_path(self, f):
        return f.get("path", None)

    def _get_field_ini_file(self, f):
        return f.get("ini_file", None)

    def _get_field_kind(self, f):
        # value: null will be interpreted with None, so let's just
        # check for the existence of the field, as we use 'value: null' to say
        # "we want a value/secret and not a file path"
        found = []
        for i in ["value", "path", "ini_file"]:
            if i in f:
                found.append(i)

        if len(found) > 1:  # you can only have one of value, path and ini_file
            self.module.fail_json(f"Both '{found[0]}' and '{found[1]}' cannot be used")

        if len(found) == 0:
            return ""
        return found[0]

    def _get_field_prompt(self, f):
        return f.get("prompt", None)

    def _get_field_base64(self, f):
        return bool(f.get("base64", False))

    def _get_field_override(self, f):
        return bool(f.get("override", False))

    # This function could use some rewriting and it should call a specific validation function
    # for each type (value, path, ini_file)
    def _validate_field(self, f):
        # These fields are mandatory
        try:
            _ = f["name"]
        except KeyError:
            return (False, f"Field {f} is missing name")

        on_missing_value = self._get_field_on_missing_value(f)
        if on_missing_value not in ["error", "generate", "prompt"]:
            return (False, f"onMissingValue: {on_missing_value} is invalid")

        value = self._get_field_value(f)
        path = self._get_field_path(f)
        ini_file = self._get_field_ini_file(f)
        kind = self._get_field_kind(f)
        if kind == "ini_file":
            # if we are using ini_file then at least ini_key needs to be defined
            # ini_section defaults to 'default' when omitted
            ini_key = f.get("ini_key", None)
            if ini_key is None:
                return (
                    False,
                    "ini_file requires at least ini_key to be defined",
                )

        # Test if base64 is a correct boolean (defaults to False)
        _ = self._get_field_base64(f)
        _ = self._get_field_override(f)

        if on_missing_value in ["error"]:
            if (
                (value is None or len(value) < 1)
                and (path is None or len(path) < 1)
                and (ini_file is None or len(ini_file) < 1)
            ):
                return (
                    False,
                    "Secret has onMissingValue set to 'error' and has neither value nor path nor ini_file set",
                )
            if path is not None and not os.path.isfile(os.path.expanduser(path)):
                return (False, f"Field has non-existing path: {path}")

            if ini_file is not None and not os.path.isfile(
                os.path.expanduser(ini_file)
            ):
                return (False, f"Field has non-existing ini_file: {ini_file}")

            if "override" in f:
                return (
                    False,
                    "'override' attribute requires 'onMissingValue' to be set to 'generate'",
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

        if on_missing_value in ["prompt"]:
            # When we prompt, the user needs to set one of the following:
            # - value: null # prompt for a secret without a default value
            # - value: 123 # prompt for a secret but use a default value
            # - path: null # prompt for a file path without a default value
            # - path: /tmp/ca.crt # prompt for a file path with a default value
            if "value" not in f and "path" not in f:
                return (
                    False,
                    "Secret has onMissingValue set to 'prompt' but has no value nor path fields",
                )

            if "override" in f:
                return (
                    False,
                    "'override' attribute requires 'onMissingValue' to be set to 'generate'",
                )

        return (True, "")

    def _validate_secrets(self):
        secrets = self._get_secrets()
        if len(secrets) == 0:
            self.module.fail_json("No secrets found")

        names = []
        for s in secrets:
            # These fields are mandatory
            for i in ["name"]:
                try:
                    _ = s[i]
                except KeyError:
                    return (False, f"Secret {s['name']} is missing {i}")
            names.append(s["name"])

            fields = s.get("fields", [])
            if len(fields) == 0:
                return (False, f"Secret {s['name']} does not have any fields")

            field_names = []
            for i in fields:
                (ret, msg) = self._validate_field(i)
                if not ret:
                    return (False, msg)
                field_names.append(i["name"])
            field_dupes = find_dupes(field_names)
            if len(field_dupes) > 0:
                return (False, f"You cannot have duplicate field names: {field_dupes}")

        dupes = find_dupes(names)
        if len(dupes) > 0:
            return (False, f"You cannot have duplicate secret names: {dupes}")
        return (True, "")

    def sanitize_values(self):
        """
        Sanitizes the secrets YAML object version 2.0

        Parameters:

        Returns:
            Nothing: Updates self.syaml(obj) if needed
        """
        v = get_version(self.syaml)
        if v != "2.0" and v != "3.0":
            self.module.fail_json(f"Version is not 2.0 or 3.0: {v}")

        backing_store = self._get_backingstore()
        if backing_store != "vault" and backing_store != "kubernetes":  # we currently only support vault
            self.module.fail_json(
                f"Currently only the 'vault' and 'kubernetes' backingStores are supported: {backing_store}"
            )

        (ret, msg) = self._validate_secrets()
        if not ret:
            self.module.fail_json(msg)

    def _get_secret_value(self, name, field):
        on_missing_value = self._get_field_on_missing_value(field)
        # We cannot use match + case as RHEL8 has python 3.9 (it needs 3.10)
        # We checked for errors in _validate_secrets() already
        if on_missing_value == "error":
            return field.get("value")
        elif on_missing_value == "prompt":
            prompt = self._get_field_prompt(field)
            if prompt is None:
                prompt = f"Type secret for {name}/{field['name']}: "
            value = self._get_field_value(field)
            if value is not None:
                prompt += f" [{value}]"
            prompt += ": "
            return getpass.getpass(prompt)
        return None

    def _get_file_path(self, name, field):
        on_missing_value = self._get_field_on_missing_value(field)
        if on_missing_value == "error":
            return os.path.expanduser(field.get("path"))
        elif on_missing_value == "prompt":
            prompt = self._get_field_prompt(field)
            path = self._get_field_path(field)
            if path is None:
                path = ""

            if prompt is None:
                text = f"Type path for file {name}/{field['name']} [{path}]: "
            else:
                text = f"{prompt} [{path}]: "

            newpath = getpass.getpass(text)
            if newpath == "":  # Set the default if no string was entered
                newpath = path

            if os.path.isfile(os.path.expanduser(newpath)):
                return newpath
            self.module.fail_json(f"File {newpath} not found, exiting")

        self.module.fail_json("File with wrong onMissingValue")

    def _inject_field(self, secret_name, f, mount, prefixes, first=False):
        pass

    def inject_secrets(self):
        pass
