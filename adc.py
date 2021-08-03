#!/usr/bin/env python3

#  Copyright 2021 Splunk Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from argparse import ArgumentParser
import json
from pathlib import Path
import re
import subprocess
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

import pandas as pd
import requests
import stix2
import yaml

__author__ = "Marcus LaFerrera (@mlaferrera)"
__version__ = "v0.4.0"


class AttackTechnique:
    def __init__(self, technique: Dict = None) -> None:
        self.technique = technique or {}
        self.name = self.technique.get("name", "Unknown")
        self.tactics = [
            p["phase_name"]
            for p in self.technique.get("kill_chain_phases", [])
            if p["kill_chain_name"] == "mitre-attack"
        ]
        self.platforms = self.technique.get("x_mitre_platforms", [])
        self.data_sources = self.technique.get("x_mitre_data_sources", [])


class TechniqueResult:
    def __init__(
        self,
        technique_id: str,
        technique: AttackTechnique,
        detections: Optional[List] = None,
    ) -> None:
        self.technique_id = technique_id
        self.name = technique.name
        self.tactics = technique.tactics
        self.detections = detections or []

    def add_detection(self, url: str, detection: str) -> None:
        self.detections.append((url, detection))

    @property
    def as_navigator(self) -> Iterable[Dict]:
        for tactic in self.tactics:
            for detection in self.detections:
                yield {
                    "techniqueID": self.technique_id,
                    "tactic": tactic,
                    "metadata": [],
                    "enabled": True,
                    "comment": "\n\n".join(
                        [f"{d[1]}: {d[0]}\n" for d in self.detections if d]
                    ),
                    "showSubtechniques": False,
                    "score": len(self.detections),
                }

    def __str__(self) -> str:
        return json.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class SplunkDetections:
    DETECTIONS_LIST = [
        "cloud",
        "endpoint",
        "network",
        "experimental/application",
        "experimental/cloud",
        "experimental/endpoint",
        "experimental/network",
        "experimental/web",
    ]

    def __init__(
        self,
        detections_root: str = None,
        repo_url: str = None,
        repo_branch: str = None,
        navigator_template: str = None,
    ) -> None:
        self.repo_branch = repo_branch or "develop"
        self.repo_url = repo_url or "https://github.com/splunk/security_content"
        self.repo_url_root = f"{self.repo_url}/blob/{self.repo_branch}/detections"
        self.detections_root = (
            Path(detections_root)
            if detections_root
            else Path("security_content/detections")
        )
        self.detections: List = []
        self.load_detections()
        self.results: List[TechniqueResult] = []
        if navigator_template:
            self.navigator_template = Path(navigator_template)

    def add_result(self, result: TechniqueResult) -> None:
        self.results.append(result)

    def load_detections(self):
        if not self.detections_root.is_dir():
            print("[!] ESCU repo not found, cloning...")
            subprocess.call(f"git clone {self.repo_url}", shell=True)
        for subdir in self.DETECTIONS_LIST:
            detection_path = self.detections_root.joinpath(subdir).resolve()
            for path in detection_path.rglob("**/*"):
                with open(path) as f:
                    uri_path = f"{subdir}{str(path).split(subdir)[1]}"
                    self.detections.append((uri_path, yaml.safe_load(f)))

    def find_technique(self, technique_id: str) -> Iterable[Tuple]:
        for path, detection in self.detections:
            if not detection:
                continue
            if technique_id in detection.get("tags", {}).get("mitre_attack_id", []):
                yield (
                    f"{self.repo_url_root}/{path}",
                    detection.get("name"),
                )

    @property
    def as_navigator(self) -> Dict:
        with open(self.navigator_template) as f:
            template = json.load(f)
        for result in self.results:
            for technique in result.as_navigator:
                if len(result.detections) > template["gradient"]["maxValue"]:
                    template["gradient"]["maxValue"] = len(result.detections)
                template["techniques"].append(technique)
        return template

    @property
    def as_html(self) -> Union[str, None]:
        data = []
        columns = [
            "ATT&CK Technique",
            "Technique/Sub-Technique Title",
            "ATT&CK Tactics",
            "Splunk Searches",
        ]
        for r in self.results:
            row = [r.technique_id, r.name, ",".join(r.tactics)]
            detection_cell = ""
            for url, detection in r.detections:
                detection_cell += f"&#8226; <a href='{url}'>{detection}</a><br/>"
            row.append(detection_cell)
            data.append(row)
        return pd.DataFrame(data, columns=columns).to_html(
            index=False, render_links=True, escape=False
        )


class AttackDB:
    ATTACK_REGEX = "(T\\d{4}(?:\\.\\d{3})?)"

    def __init__(self, domain: Optional[str] = None, update: bool = False) -> None:
        self.domain: str = domain or "enterprise-attack"
        self.memorystore: stix2.MemoryStore = self._get_cache(self.domain, update)

    def find_technique(self, technique: str) -> AttackTechnique:
        result = self.memorystore.query(
            [stix2.Filter("external_references.external_id", "=", technique)]
        )
        if result:
            return AttackTechnique(result[0])
        return AttackTechnique()

    @staticmethod
    def unique_ids(ids: List[str]) -> Set[str]:
        ids.sort()
        return set([i.strip() for i in ids])

    @staticmethod
    def extract_ids(data: str) -> Set[str]:
        ids = re.findall(AttackDB.ATTACK_REGEX, data)
        return AttackDB.unique_ids(ids)

    @staticmethod
    def _get_cache(
        domain: str = "enterprise-attack", update: bool = False
    ) -> stix2.MemoryStore:
        cache_file = Path(f"{domain}.json").resolve()
        if update or not cache_file.exists():
            stix_json = requests.get(
                f"https://raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json"
            ).json()
            cache_file.write_text(json.dumps(stix_json))
        else:
            with open(cache_file, "r") as f:
                stix_json = json.loads(f.read())

        return stix2.MemoryStore(stix_data=stix_json["objects"])


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "-e",
        "--extract-ids",
        default=None,
        nargs="+",
        help="Extract ATT&CK Techniques IDs from file or URL",
    )
    parser.add_argument(
        "-t", "--technique-ids", nargs="+", help="ATT&CK Techniques IDs to find"
    )
    parser.add_argument(
        "-d",
        "--detections",
        default=None,
        help="Path to ESCU detections root",
    )
    parser.add_argument(
        "-o", "--outfile", default=None, help="Filename to save results to"
    )
    parser.add_argument(
        "--as-navigator",
        action="store_true",
        default=False,
        help="Save results as ATT&CK Navigator instead of HTML table",
    )

    parser.add_argument(
        "--attack-domain",
        default="enterprise-attack",
        choices=["enterprise-attack", "mobile-attack", "pre-attack"],
        help="ATT&CK Framework to leverage",
    )
    parser.add_argument(
        "--update-cache",
        action="store_true",
        default=False,
        help="Update the locally cached ATT&CK database",
    )

    args = parser.parse_args()

    technique_ids: Set[str] = set()
    detection_count: int = 0

    if args.technique_ids:
        technique_ids.update(AttackDB.unique_ids(args.technique_ids))

    if args.extract_ids:
        data = ""
        for src in args.extract_ids:
            if src.startswith("http"):
                data += requests.get(src).text
            else:
                with open(src, "r") as f:
                    data += f.read()
        technique_ids.update(AttackDB.extract_ids(data))

    if not technique_ids:
        parser.print_help()
        exit(-1)

    sd = SplunkDetections(
        args.detections, navigator_template="attack-navigator-template.json"
    )
    attackdb = AttackDB(args.attack_domain, args.update_cache)

    for technique_id in technique_ids:
        technique = attackdb.find_technique(technique_id)
        result = TechniqueResult(technique_id=technique_id, technique=technique)
        for url, detection in sd.find_technique(technique_id):
            result.add_detection(url, detection)
            detection_count += 1
        sd.add_result(result)

    if args.as_navigator:
        output = json.dumps(sd.as_navigator)
    else:
        output = sd.as_html or str()

    if args.outfile:
        with open(args.outfile, "w") as outfile:
            outfile.write(output)
    else:
        print(output)

    print(
        f"[*] Technique IDs queried: {', '.join(technique_ids)}({len(technique_ids)}), found {detection_count} detections."
    )
