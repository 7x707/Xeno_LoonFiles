from pathlib import Path
from urllib.request import Request, urlopen
import re

SOURCES_FILE = Path("sources.txt")
OUTPUT_DIR = Path("dist")
OUTPUT_FILE = OUTPUT_DIR / "Xeno.plugin"

SECTION_NAMES = [
    "Argument",
    "General",
    "Rule",
    "Rewrite",
    "Host",
    "Script",
    "Mitm",
]

SECTION_LOOKUP = {
    name.lower(): name
    for name in SECTION_NAMES
}

sections = {
    name: []
    for name in SECTION_NAMES
}

seen = {
    name: set()
    for name in SECTION_NAMES
}

mitm_hosts = []
mitm_host_seen = set()

# 用于检查容易发生冲突的 key
key_values = {
    "Argument": {},
    "General": {},
    "Host": {},
}


def download(url):
    print(f"Downloading: {url}")

    request = Request(
        url,
        headers={
            "User-Agent": "Loon-Plugin-Collection/1.0"
        },
    )

    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8-sig")


def add_normal_line(section, line, source):
    stripped = line.strip()

    if not stripped:
        return

    if stripped.startswith("#"):
        return

    # Argument / General / Host 检查相同 key 是否冲突
    if section in key_values and "=" in stripped:
        key = stripped.split("=", 1)[0].strip()

        if key:
            old = key_values[section].get(key)

            if old and old != stripped:
                raise RuntimeError(
                    f"\nConflict detected!\n"
                    f"Section: [{section}]\n"
                    f"Key: {key}\n"
                    f"Existing: {old}\n"
                    f"New: {stripped}\n"
                    f"Source: {source}\n"
                )

            key_values[section][key] = stripped

    if stripped not in seen[section]:
        seen[section].add(stripped)
        sections[section].append(stripped)


def parse_plugin(content, source):
    current_section = None

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        # 忽略原插件 metadata
        if line.startswith("#!"):
            continue

        # Section
        match = re.fullmatch(r"\[([^\]]+)\]", line)

        if match:
            name = match.group(1).strip().lower()
            current_section = SECTION_LOOKUP.get(name)
            continue

        if current_section is None:
            continue

        # MitM hostname 特殊处理
        if current_section == "Mitm":
            hostname_match = re.match(
                r"^hostname\s*=\s*(.*)$",
                line,
                re.IGNORECASE,
            )

            if hostname_match:
                hostname_text = hostname_match.group(1)

                for host in hostname_text.split(","):
                    host = host.strip()

                    if not host:
                        continue

                    if host not in mitm_host_seen:
                        mitm_host_seen.add(host)
                        mitm_hosts.append(host)

                continue

        add_normal_line(
            current_section,
            line,
            source,
        )


def read_sources():
    sources = []

    for line in SOURCES_FILE.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        sources.append(line)

    return sources


def build():
    sources = read_sources()

    if not sources:
        raise RuntimeError("sources.txt 没有插件地址")

    for url in sources:
        content = download(url)
        parse_plugin(content, url)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = []

    output.extend([
        "#!name = Xeno Plugin Collection",
        "#!desc = Automatically merged Loon plugins",
        "#!author = Xeno",
        "#!tag = Collection",
        "#!type = normal",
        "",
    ])

    for section in SECTION_NAMES:
        lines = sections[section]

        if section == "Mitm":
            if not lines and not mitm_hosts:
                continue
        elif not lines:
            continue

        output.append(f"[{section}]")

        for line in lines:
            output.append(line)

        if section == "Mitm" and mitm_hosts:
            output.append(
                "hostname = " + ",".join(mitm_hosts)
            )

        output.append("")

    OUTPUT_FILE.write_text(
        "\n".join(output),
        encoding="utf-8",
    )

    print()
    print(f"Generated: {OUTPUT_FILE}")
    print(f"Sources: {len(sources)}")


if __name__ == "__main__":
    build()
