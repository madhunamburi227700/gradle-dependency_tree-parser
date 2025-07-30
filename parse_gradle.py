import json
import os
import re
import sys
from typing import List, Dict

CONFIG_LINE_RE = re.compile(r'^[A-Za-z].* - .*')
DEP_LINE_RE = re.compile(r'^\s*[\|\s\\+]*[+\\-]---\s+(.+)$')
DEP_PREFIX_RE = re.compile(r'^(\s*[\|\s\\+]*?)[+\\-]---')

# --------------------- Models --------------------- #

class Dependency:
    def __init__(self, group, name, version, constraint=False, omitted=False, resolved=True):
        self.group = group.strip()
        self.name = name.strip()
        self.version = version.strip()
        self.constraint = constraint
        self.omitted = omitted
        self.resolved = resolved
        self.classification = self.classify()
        self.dependencies = []

    def classify(self):
        group = self.group.lower()
        name = self.name.lower()

        if name.endswith("-bom"):
            return "bom"
        elif "groovy" in group:
            return "groovy"
        elif group.startswith("org.apache"):
            return "apache"
        elif "spinnaker" in group or "kork" in name:
            return "spinnaker"
        elif group.startswith("org.springframework.boot") or "spring-boot" in name:
            return "spring-starter"
        elif "springframework" in group:
            return "spring"
        elif any(word in name for word in ["log4j", "slf4j", "logback", "logging"]):
            return "logging"
        elif any(word in name for word in ["micrometer", "prometheus"]):
            return "monitoring"
        elif any(db in name for db in ["mysql", "postgres", "h2", "sqlite", "jdbc", "r2dbc"]):
            return "database"
        elif any(word in name for word in ["security", "auth0", "jwt"]):
            return "security"
        elif any(word in name for word in ["okhttp", "retrofit", "httpclient"]):
            return "http-client"
        elif "jackson" in name or group.startswith("com.fasterxml.jackson"):
            return "json"
        elif group.startswith("com.google"):
            return "google-lib"
        elif group.startswith("org.jetbrains.kotlin") or "kotlin" in group:
            return "kotlin"
        elif group in ["com.amazonaws", "software.amazon", "cloud.google", "com.azure"]:
            return "cloud"
        elif "reactor" in name or group == "io.projectreactor":
            return "reactive"
        elif any(word in name for word in ["test", "junit", "mockito"]):
            return "test-lib"
        else:
            return "library"

    def to_dict(self):
        result = {
            "group": self.group,
            "name": self.name,
            "version": self.version,
            "id": f"{self.group}:{self.name}:{self.version}",
            "class": self.classification,
        }
        if self.constraint:
            result["constraint"] = True
        if self.omitted:
            result["omitted"] = True
        if not self.resolved:
            result["resolved"] = False
        if self.dependencies:
            result["dependencies"] = [dep.to_dict() for dep in self.dependencies]
        return result


class Configuration:
    def __init__(self, name, source_set=None, resolved=True):
        self.name = name
        self.source_set = source_set
        self.resolved = resolved
        self.dependencies = []

    def to_dict(self):
        return {
            "name": self.name,
            "sourceSet": self.source_set,
            "resolved": self.resolved,
            "dependencies": [dep.to_dict() for dep in self.dependencies]
        }


# --------------------- Parser --------------------- #

class GradleDependencyParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.configurations = []
        self.stack = []

    def parse(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: File '{self.file_path}' not found.")
            return {"configurations": []}

        current_config = None

        for raw_line in lines:
            stripped = raw_line.strip()

            if CONFIG_LINE_RE.match(stripped):
                config_name = stripped.split(' - ')[0].strip()
                resolved = '(n)' not in stripped
                match = re.search(r"source set '(.*?)'", stripped)
                source_set = match.group(1) if match else None

                current_config = Configuration(config_name, source_set, resolved)
                self.configurations.append(current_config)
                self.stack.clear()
                continue

            m = DEP_LINE_RE.match(raw_line)
            if not m or current_config is None:
                continue

            notation_line = m.group(1).strip()
            dependency = self.create_dependency(notation_line)
            if not dependency:
                continue

            depth = self.get_depth(raw_line)

            while self.stack and self.stack[-1]["depth"] >= depth:
                self.stack.pop()

            if self.stack:
                parent = self.stack[-1]["node"]
                parent.dependencies.append(dependency)
            else:
                current_config.dependencies.append(dependency)

            self.stack.append({"depth": depth, "node": dependency})

        return {"configurations": [cfg.to_dict() for cfg in self.configurations]}

    def create_dependency(self, notation_line):
        constraint = "(c)" in notation_line
        omitted = "(*)" in notation_line
        not_resolved = "(n)" in notation_line

        notation_line = (
            notation_line.replace("(c)", "")
                         .replace("(*)", "")
                         .replace("(n)", "")
                         .strip()
        )

        if '->' in notation_line:
            left, right = notation_line.split('->', 1)
            group_name = left.strip()
            version = right.strip()
            parts = group_name.split(':')
            if len(parts) < 2:
                return None
            group, name = parts[0], parts[1]
        else:
            parts = notation_line.split(':')
            if len(parts) >= 3:
                group, name, version = parts[:3]
            elif len(parts) == 2:
                group, name = parts
                version = "unspecified"
            else:
                return None

        return Dependency(
            group, name, version,
            constraint=constraint,
            omitted=omitted,
            resolved=not not_resolved
        )

    def get_depth(self, line):
        m = DEP_PREFIX_RE.match(line)
        if not m:
            return 0
        prefix = m.group(1)
        norm = re.sub(r'[|\\+]', ' ', prefix)
        return len(norm) // 4


# --------------------- Tracer --------------------- #

class DependencyTracer:
    def __init__(self, input_data: Dict, output_file: str = "result.json"):
        self.data = input_data
        self.output_file = output_file

    def find_all_dependency_paths(self, dependencies, target_id, path=None) -> List[List[Dict]]:
        if path is None:
            path = []
        matches = []
        for dep in dependencies:
            current_path = path + [dep]
            if dep.get("id") == target_id:
                matches.append(current_path)
            if "dependencies" in dep:
                matches += self.find_all_dependency_paths(dep["dependencies"], target_id, current_path)
        return matches

    def build_id_only_tree(self, path: List[Dict]) -> Dict:
        if not path:
            return {}
        root = {"id": path[0]["id"], "dependencies": []}
        current = root
        for node in path[1:]:
            child = {"id": node["id"], "dependencies": []}
            current["dependencies"].append(child)
            current = child
        return root

    def trace_dependency(self, target_id: str) -> Dict:
        results = []
        configurations_found = []

        for config in self.data.get("configurations", []):
            deps = config.get("dependencies", [])
            all_paths = self.find_all_dependency_paths(deps, target_id)

            if all_paths:
                config_result = {
                    "configuration": config["name"],
                    "occurrences": len(all_paths),
                    "chains": [self.build_id_only_tree(path) for path in all_paths]
                }
                results.append(config_result)
                configurations_found.append(config["name"])

        if not results:
            return {}

        return {
            "target_dependency": target_id,
            "total_occurrences": sum(r["occurrences"] for r in results),
            "found_in_configurations": configurations_found,
            "results": results
        }

    def save_result(self, output_entry: Dict) -> None:
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump([output_entry], f, indent=2)

    def print_summary(self, output_entry: Dict) -> None:
        print(f"\nFound in {len(output_entry['results'])} configuration(s):")
        for r in output_entry["results"]:
            print(f"  configuration: {r['configuration']} ({r['occurrences']} occurrences)")
            for i, tree in enumerate(r["chains"], 1):
                print(f"    Path {i}:")
                self.print_id_tree(tree, indent_level=3)
        print(f"\nSaved result to {self.output_file}\n")

    def print_id_tree(self, tree: Dict, indent_level=0) -> None:
        indent = "  " * indent_level
        print(f"{indent}{tree['id']}")
        for child in tree.get("dependencies", []):
            self.print_id_tree(child, indent_level + 1)


# --------------------- Main --------------------- #

def main():
    input_txt = "igor-core.txt"
    json_output = "igor-core-depend.json"

    # Parse text file into structured JSON
    parser = GradleDependencyParser(input_txt)
    parsed_data = parser.parse()

    # Save parsed output
    with open(json_output, "w", encoding="utf-8") as f:
        json.dump(parsed_data, f, indent=2)
    print(f"Parsed output saved to {json_output}")

    # Trace specific dependency
    tracer = DependencyTracer(parsed_data)

    while True:
        target_dependency = input("🔍 Enter the dependency (group:name:version), or 'exit' to quit: ").strip()
        if target_dependency.lower() in ["exit", "quit", "q"]:
            print("Exiting.")
            break
        if not target_dependency.count(":") == 2:
            print("Please provide a valid dependency in 'group:name:version' format.\n")
            continue

        result = tracer.trace_dependency(target_dependency)
        if not result:
            print("Dependency not found in any configuration.\n")
            continue

        tracer.save_result(result)
        tracer.print_summary(result)

if __name__ == "__main__":
    main()
