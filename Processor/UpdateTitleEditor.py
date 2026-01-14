#!/usr/local/autopkg/python

import os
import plistlib
import shutil
import xml
import subprocess
import json
import re
from collections import namedtuple
from datetime import datetime, timedelta
from glob import glob

from base64 import b64encode
from autopkglib import ProcessorError
from autopkglib.FlatPkgUnpacker import FlatPkgUnpacker
from autopkglib.PkgPayloadUnpacker import PkgPayloadUnpacker

"""
Based off of NotifyPatchServer.py - \
https://github.com/autopkg/lrz-recipes/blob/main/SharedProcessors/NotifyPatchServer.py
########  2020 LRZ - Christoph Ostermeier

SECURITY NOTICE: This processor now uses macOS Keychain for credential storage.
 
Setup Instructions:
1. Run the setup script to store credentials in Keychain:
    python setup_keychain_credentials.py

2. The script will prompt for:
    - Title Editor URL (e.g., https://your.title.url)
    - Username
    - Password

3. Credentials are stored in Keychain under service name "title-editor"

Legacy Support:
For backward compatibility, the processor will fall back to AutoPkg preferences
if Keychain credentials are not found. However, this is NOT recommended for security.

Set Title Editor URL
## Add TITLE_URL to your autopkg prefs (do NOT include trailing slash in the the URL) -
    defaults write com.github.autopkg TITLE_URL https://your.title.url

## Add TITLE_USER and TITLE_PASS to your autopkg prefs -
    defaults write com.github.autopkg TITLE_USER title-editor-user
    defaults write com.github.autopkg TITLE_PASS "title-editor-pass"
"""

"""See docstring for UpdateTitleEditor class"""

__all__ = ["UpdateTitleEditor"]


class UpdateTitleEditor(PkgPayloadUnpacker, FlatPkgUnpacker):
    """
    This is a Post-Processor for AutoPkg.
    It unpacks the newly generated Package, searches for an App-Bundle and \
    extracts all Information needed forupdating Title Editor. The unpacked \
    data will be removed from disk afterwards.
    """

    description = __doc__

    input_variables = {
        "pkg_vers_key": {
            "required": False,
            "description": "Plist Version Key to read",
            },
        "patch_name": {
            "required": False,
            "description": "patch name for patch server.",
        },
        "forcevers": {
            "required": False,
            "description": "forced version from variable in previous step of \
            recipe",
        },
        "app_plist_path": {
            "required": False,
            "description": "path from cache_dir to app containing plist"
        },
        "app": {
            "required": False,
            "description": "plist file"
        },
        "debug": {
            "required": False,
            "description": "Flag to enable debugging - run with --key debug=true"
        },        
        "title_id": {
            "required": True,
            "description": "Title Editor Numeric ID"
        }
    }

    output_variables = {
        "patchJson": {
            "description": "patch data.",
            },
        "patch_id": {
            "description": "patch data.",
            },
        "verJson": {
            "description": "actual version string.",
            },
        "title_updated": {
            "description": "true if title def was updated",
            }
    }

    # Required for FlatPkgUnpacker
    source_path = None
    # Remove these directories after processing
    cleanupDirs = []

    title_updated = False
    
    # Keychain configuration
    KEYCHAIN_SERVICE = "title-editor"
    KEYCHAIN_URL_ACCOUNT = "url"
    KEYCHAIN_USER_ACCOUNT = "username"
    KEYCHAIN_PASS_ACCOUNT = "password"
    
    # Token caching (tokens typically expire after 30 minutes)
    cached_token = None
    token_expiry = None
    TOKEN_LIFETIME_MINUTES = 25  # Refresh 5 minutes before expiration

    def unpack(self):
        """Unpacks the Package file using other Processors"""
        # Emulate FlatPkgUnpacker/main-method
        self.env["destination_path"] = \
            os.path.join(self.env["RECIPE_CACHE_DIR"], "UnpackedPackage")
        self.cleanupDirs.append(self.env["destination_path"])
        self.output("Unpacking '%s' to '%s'" % (self.env["pkg_path"],
                    self.env["destination_path"]))
        self.source_path = self.env["pkg_path"]
        self.unpack_flat_pkg()
        # Emulate PkgPayloadUnpacker/main-method
        self.env["pkg_payload_path"] = \
            os.path.join(self.env["destination_path"], "Payload")
        # If there is a payload already, unpack it
        if os.path.isfile(self.env["pkg_payload_path"]):
            matches, app_glob_path = self.find_app()
        else:
            # Sometimes there is no Payload, so we have to find the .pkg which
            # contains it.
            pkgs = os.path.join(self.env["destination_path"], "*.pkg",
                                "Payload")
            payloadmatches = glob(pkgs)
            if len(payloadmatches) == 0:
                ProcessorError("No Subpackage found by globbing %s" % pkgs)
            else:
                for payloadmatch in payloadmatches:
                    self.env["pkg_payload_path"] = payloadmatch
                    matches, app_glob_path = self.find_app()
                    if len(matches) > 0:
                        break
        if len(matches) == 0:
            ProcessorError("No match found by globbing %s" % app_glob_path)
        elif len(matches) > 1:
            ProcessorError("Multiple matches found by globbing %s" %
                           app_glob_path)
        else:
            self.output("Found %s" % matches[0])
            return matches[0]

    def genPatchVersion(self, app_path):
        """Generates a PatchVersion based on the current AppBundle"""
        # Extract the Filename and open the Info.plist
        patch_title_id = self.env["title_id"]
        if self.env.get("app_plist_path"):
            app_path = self.env["app_plist_path"]
        filename = os.path.basename(app_path.rstrip("/"))
        info_plist_path = os.path.join(app_path, "Contents", "Info.plist")
        # Try to extract data to an hashtable
        try:
            with open(info_plist_path, 'rb') as fp:
                info_plist = plistlib.load(fp)
        except EnvironmentError as err:
            print('ERROR: {}'.format(err))
            raise SystemExit(1)
        except xml.parsers.expat.ExpatError:
            info_plist = self.read_binary_plist(info_plist_path)

        if self.env.get("forcevers"):
            pkgversion = self.env["forcevers"]
        elif self.env.get("pkg_vers_key"):
            pkgversion = info_plist[self.env["pkg_vers_key"]]
        else:
            pkgversion = self.env["version"]

        useVer = pkgversion
        """ Grab name (with spaces) and id (without spaces) + bundleId
            and Version from Info.plist"""
        name = filename.replace('.app', '')
        try:
            if self.env.get("patch_name"):
                patch_id = self.env["patch_name"]
            else:
                patch_id = info_plist["CFBundleName"].replace(' ', '')
        except KeyError:
            patch_id = name.replace(' ', '')
        patch_id = self.env["title_id"]
        bundle_id = info_plist["CFBundleIdentifier"]

        # If a minimumOperatingSystem is set, use that
        try:
            min_os = info_plist["LSMinimumSystemVersion"]
        except KeyError:
            min_os = "10.9"

        # get timestamps
        timestamp = datetime.utcfromtimestamp(
            os.path.getmtime(app_path)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # generate patchData
        patch = json.dumps(
            {"patchId": 0, "softwareTitleId": patch_id,
             "absoluteOrderId": 0, "version": useVer,
             "releaseDate": timestamp, "standalone": True,
             "minimumOperatingSystem": min_os, "reboot": False,
             "killApps": [{"bundleId": bundle_id,
                           "appName": filename}],
             "components": [{"name": name, "version": useVer,
                            "criteria": [{"name": "Application Bundle ID",
                                          "operator": "is", "value": bundle_id,
                                          "type": "recon", "and": True},
                                         {"name": "Application Version",
                                          "operator": "is", "value": useVer,
                                          "type": "recon"}]}],
             "capabilities": [{"name": "Operating System Version",
                               "operator": "greater than or equal",
                               "value": min_os, "type": "recon"}],
             "dependencies": []})
        self.env['patchJson'] = patch
        verJson = json.dumps({"currentVersion": useVer,
                              "softwareTitleId": patch_id})
        self.env['verJson'] = verJson

        return patch_id, patch, verJson

    def log_with_timestamp(self, message):
        """Log message with timestamp for audit trail."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.output(f"[{timestamp}] {message}")

    def get_keychain_value(self, service, account):
        """Retrieve a value from macOS Keychain."""
        try:
            result = subprocess.run(
                ['security', 'find-generic-password',
                 '-s', service, '-a', account, '-w'],
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def get_credentials_from_keychain(self):
        """Get credentials from macOS Keychain."""
        url = self.get_keychain_value(self.KEYCHAIN_SERVICE, self.KEYCHAIN_URL_ACCOUNT)
        username = self.get_keychain_value(self.KEYCHAIN_SERVICE, self.KEYCHAIN_USER_ACCOUNT)
        password = self.get_keychain_value(self.KEYCHAIN_SERVICE, self.KEYCHAIN_PASS_ACCOUNT)
        
        if url and username and password:
            self.log_with_timestamp("Credentials retrieved from macOS Keychain")
            return url, username, password
        return None, None, None

    def get_credentials_from_env(self):
        """Get credentials from environment variables."""
        url = os.environ.get("TITLE_EDITOR_URL")
        username = os.environ.get("TITLE_EDITOR_USER")
        password = os.environ.get("TITLE_EDITOR_PASS")
        
        if url and username and password:
            self.log_with_timestamp("Credentials retrieved from environment variables")
            return url, username, password
        return None, None, None

    def get_credentials_from_prefs(self):
        """Get credentials from AutoPkg preferences (legacy fallback)."""
        url = self.env.get("TITLE_URL")
        username = self.env.get("TITLE_USER")
        password = self.env.get("TITLE_PASS")
        
        if url and username and password:
            self.output("WARNING: Using credentials from AutoPkg preferences.")
            self.output("For better security, run setup_keychain_credentials.py")
            self.log_with_timestamp("Credentials retrieved from AutoPkg preferences (insecure)")
            return url, username, password
        return None, None, None

    def get_enc_creds(self, user=None, password=None):
        """Get credentials and encode them for Basic Auth.
        
        Tries to get credentials in this order:
        1. macOS Keychain (recommended)
        2. Environment variables (for CI/CD)
        3. AutoPkg preferences (legacy fallback)
        """
        # Try Keychain first
        url, username, password = self.get_credentials_from_keychain()
        
        # Fall back to environment variables
        if not all([url, username, password]):
            url, username, password = self.get_credentials_from_env()
        
        # Fall back to AutoPkg preferences if still empty
        if not all([url, username, password]):
            url, username, password = self.get_credentials_from_prefs()
        
        # If still no credentials, raise error
        if not all([url, username, password]):
            self.output("No credentials found in Keychain, environment, or AutoPkg preferences")
            self.output("Please run setup_keychain_credentials.py to configure")
            raise ProcessorError("No Title Editor credentials found")
        
        # Store URL in env for later use
        if not self.env.get("TITLE_URL"):
            self.env["TITLE_URL"] = url
        
        # Encode credentials for Basic Auth
        credentials = f"{username}:{password}"
        enc_creds_bytes = b64encode(credentials.encode("utf-8"))
        enc_creds = str(enc_creds_bytes, "utf-8")
        return enc_creds

    def get_cached_token(self):
        """Return cached token if still valid, otherwise None."""
        if self.cached_token and self.token_expiry:
            if datetime.utcnow() < self.token_expiry:
                self.log_with_timestamp("Using cached authentication token")
                return self.cached_token
            else:
                self.log_with_timestamp("Cached token expired, requesting new token")
        return None

    def get_api_token(self, jamf_url, enc_creds):
        """Get a token for the Jamf Pro API or Classic API for Jamf Pro 10.35+.
        
        Implements token caching to reduce authentication requests.
        Tokens are cached for 25 minutes (5 minutes before 30-minute expiration).
        """
        # Check for cached token first
        cached = self.get_cached_token()
        if cached:
            return cached
        
        if self.env.get("TITLE_URL"):
            jamf_url = self.env.get("TITLE_URL")
        else:
            self.output("Title URL is not in prefs")
            raise ProcessorError("No Title Editor URL supplied")
        
        url = jamf_url + "/v2/auth/tokens"
        self.log_with_timestamp("Requesting new authentication token")
        
        try:
            r, httpcode = self.curl(request="POST", url=url, enc_creds=enc_creds)
            
            if httpcode not in (200, 201):
                self.output(f"ERROR: Authentication failed with HTTP {httpcode}")
                raise ProcessorError(f"Authentication failed: HTTP {httpcode}")
            
            token = str(r["token"])
            expires = str(r["expires"])
            
            # Cache the token
            self.cached_token = token
            self.token_expiry = datetime.utcnow() + \
                timedelta(minutes=self.TOKEN_LIFETIME_MINUTES)
            
            self.log_with_timestamp("Successfully obtained authentication token")
            return token
            
        except KeyError:
            self.output("ERROR: No token received in response")
            raise ProcessorError("Authentication failed: No token in response")
        except Exception as e:
            self.output(f"ERROR: Authentication request failed: {e}")
            raise ProcessorError(f"Authentication failed: {e}")

    def curl(
            self,
            request="",
            url="",
            token="",
            enc_creds="",
            data="",
            additional_headers="",
            ):
        """ Setup the curl command """
        if url:
            curl_cmd = [
                "/usr/bin/curl",
                "--silent",
                "--show-error",
                url
            ]
            curl_cmd.extend(["--header", "Content-Type: application/json"])
            curl_cmd.extend(["-w", "\n%{http_code}"])
        else:
            raise ProcessorError("No URL supplied")

        if request:
            curl_cmd.extend(["--request", request])

        if enc_creds:
            curl_cmd.extend(["--header", f"Authorization: Basic {enc_creds}"])
        elif token:
            curl_cmd.extend(["--header", f"authorization: Bearer {token}"])

        if data:
            curl_cmd.extend(["--data", data])

        proc = subprocess.Popen(curl_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        (out, err) = proc.communicate()

        length = len(out.decode())
        httpcode = int(out.decode()[-3:])

        jsonload = out.decode()[0:length - 3]
        jsonoutput = json.loads(jsonload)

        return jsonoutput, httpcode

    def validate_credentials(self, jamf_url, enc_creds):
        """Validate credentials by attempting to get a token.
        
        Returns True if credentials are valid, False otherwise.
        This is called before the main workflow to catch auth issues early.
        """
        try:
            self.log_with_timestamp("Validating credentials...")
            token = self.get_api_token(jamf_url, enc_creds)
            if token:
                self.log_with_timestamp("Credential validation successful")
                return True
            return False
        except Exception as e:
            self.output(f"Credential validation failed: {e}")
            return False

    def notifyServer(self, id, patchData, currentData):
        # Get credentials (from Keychain, env vars, or prefs) and encode them
        enc_creds = self.get_enc_creds()
        
        # Get URL (should be set by get_enc_creds if from Keychain)
        if self.env.get("TITLE_URL"):
            my_url = self.env.get("TITLE_URL")
        else:
            self.output("Title URL not found")
            raise ProcessorError("No Title Editor URL supplied")
        
        # Validate credentials before proceeding
        if not self.validate_credentials(my_url, enc_creds):
            raise ProcessorError("Credential validation failed. Please check your credentials.")
        
        authtoken = self.get_api_token(my_url, enc_creds)
        version = self.env["version"]
        title = self.env.get("NAME")

        """Sends the new PatchVersion to a PatchServer"""

        # Build url for the Patchtitle
        patchUrl = "%s/v2/softwaretitles/%s/patches" % (my_url, id)
        # Fire Request
        headers = {"Accept": "application/json"}
        r, httpcode = self.curl(request="POST", url=patchUrl,
                                additional_headers=headers,
                                token=authtoken, data=patchData)
        if httpcode in (200, 201):
            self.output("New version - setting currentVersion")
            versionUrl = "%s/v2/softwaretitles/%s" % (my_url, id)
            r, verhttpcode = self.curl(request="PUT", url=versionUrl,
                                       data=currentData, token=authtoken)
            # Get errors if any
            if verhttpcode not in (200, 201):
                raise ProcessorError("Error %s setting version for %s"
                                     % (verhttpcode, title))
            else:
                self.title_updated = True
        elif httpcode == 400:
            errData = r["errors"][0]["code"]
            if errData == 'DUPLICATE_RECORD':
                self.output("%s was already at this version" % title)
            else:
                raise ProcessorError("Error %s sending Patch-Data for %s: %s"
                                     % (httpcode, title, errData))
        else:
            raise ProcessorError("Error %s sending Patch-Data for %s: %s"
                                 % (httpcode, title, r))
        
        self.env["title_updated"] = self.title_updated


    def cleanup(self):
        """Directory cleanup"""
        for directory in self.cleanupDirs:
            if os.path.isdir(directory):
                shutil.rmtree(directory)

    def main(self):
        app_path = self.unpack()
        patch_id, patchData, verJson = self.genPatchVersion(app_path)
        self.notifyServer(patch_id, patchData, verJson)
        self.cleanup()

    def find_app(self):
        """Helper Function to unpack Payloads"""
        self.env["destination_path"] = os.path.join(self.env["RECIPE_CACHE_DIR"],
                                                    "UnpackedPayload")
        self.cleanupDirs.append(self.env["destination_path"])
        self.output("Unpacking Payload to'%s'" % self.env["destination_path"])
        self.unpack_pkg_payload()
        # Find Application in unpacked Payload and return the Path
        # Try it in Apps Folder
        app_glob_path = os.path.join(self.env["destination_path"],
                                     "Applications", "*.app")
        matches = glob(app_glob_path)
        if len(matches) > 0:
            return matches, app_glob_path
        else:
            # Afterwards try it directly, fixes it for Virtualbox.
            app_glob_path = os.path.join(self.env["destination_path"], "*.app")
            return glob(app_glob_path), app_glob_path

    def read_binary_plist(self, plist_path):
        process = subprocess.Popen(
            ['plutil', '-convert', 'json', '-o', '-', plist_path],
            stdout=subprocess.PIPE
        )
        response = process.communicate()
        try:
            return json.loads(response[0])
        except ValueError:
            print('ERROR: Unable to read the application plist!')
            raise SystemExit(1)

    def debug_log(self,message,sub_string):
        ''' To use: add 
        self.debug_log("Text to desplay after DEBUG - ",variabledata)
        '''
        if self.env.get("debug"):
            print(("DEBUG - %s is %s") % (message, sub_string))

if __name__ == "__main__":
    PROCESSOR = UpdateTitleEditor()
    PROCESSOR.execute_shell()
