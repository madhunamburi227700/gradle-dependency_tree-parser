import json
import re
import sys


CONFIG_LINE_RE = re.compile(r'^[A-Za-z].* - .*')
# matches lines starting with optional pipes/spaces/plus/backslashes and then +--- or \--- or --- etc.
DEP_LINE_RE = re.compile(r'^\s*[\|\s\\+]*[+\\-]---\s+(.+)$')
# to compute depth, capture the prefix before the +--- / \---
DEP_PREFIX_RE = re.compile(r'^(\s*[\|\s\\+]*?)[+\\-]---')


def parse_gradle_dependencies(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return {"configurations": []}

    configurations = []
    current_config = None
    stack = []  # stack of {"depth": int, "node": dict}

    def create_dependency(notation_line):
        """
        Turn one Gradle notation line (already trimmed after the --- marker)
        into a dict {group,name,version,...}.
        """
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
            # example: com.foo:bar -> 1.2.3
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
            elif len(parts) == 2:  # no explicit version shown
                group, name = parts
                version = "unspecified"
            else:
                return None

        dep = {
            "group": group.strip(),
            "name": name.strip(),
            "version": version.strip()
        }
        if constraint:
            dep["constraint"] = True
        if omitted:
            dep["omitted"] = True
        if not_resolved:
            dep["resolved"] = False
        return dep

    def get_depth(line):
        """
        Compute the nesting depth of a dependency line from its visual prefix.
        Gradle typically uses groups like '|    ' (4–5 chars). We'll normalize
        all non-space tree chars to spaces and divide by 4 to be tolerant.
        """
        m = DEP_PREFIX_RE.match(line)
        if not m:
            return 0
        prefix = m.group(1)
        # normalize anything that is not a space to a space, then count spaces
        norm = re.sub(r'[|\\+]', ' ', prefix)
        # collapse consecutive spaces to keep it simple, but the important part
        # is to use a consistent divisor (4 is usually safe).
        return len(norm) // 4

    for raw_line in lines:
        stripped = raw_line.strip()

        # ---- configuration line ------------------------------------------------
        if CONFIG_LINE_RE.match(stripped):
            config_name = stripped.split(' - ')[0].strip()
            resolved = '(n)' not in stripped
            match = re.search(r"source set '(.*?)'", stripped)
            source_set = match.group(1) if match else None

            current_config = {
                "name": config_name,
                "sourceSet": source_set,
                "resolved": resolved,
                "dependencies": []
            }
            configurations.append(current_config)
            stack.clear()
            continue

        # ---- dependency line ---------------------------------------------------
        m = DEP_LINE_RE.match(raw_line)
        if not m:
            continue  # ignore anything else

        if current_config is None:
            # Safety: if somehow a dependency appears before any configuration line
            continue

        notation = m.group(1).strip()
        dep = create_dependency(notation)
        if not dep:
            continue

        depth = get_depth(raw_line)

        # pop until we are at the parent depth
        while stack and stack[-1]["depth"] >= depth:
            stack.pop()

        if stack:
            parent = stack[-1]["node"]
            parent.setdefault("dependencies", []).append(dep)
        else:
            current_config["dependencies"].append(dep)

        stack.append({"depth": depth, "node": dep})

    return {"configurations": configurations}


# --- Run ---
if __name__ == '__main__':
    input_file = sys.argv[1] if len(sys.argv) > 1 else "depend.txt"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "depend.json"

    result = parse_gradle_dependencies(input_file)

    try:
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(result, f, indent=2)
        print(f"✅ Output saved to {output_file}")
    except Exception as e:
        print(f"Error writing JSON file: {e}")
