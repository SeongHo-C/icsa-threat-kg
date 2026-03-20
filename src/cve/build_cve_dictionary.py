import json
import pandas as pd
from pathlib import Path

start_year = 2016
end_year = 2025


def resolve_base_dir():
    current_dir = Path.cwd().resolve()

    for path in [current_dir, *current_dir.parents]:
        if (path / 'data').exists():
            return path

    raise FileNotFoundError("Could not find project root containing 'data' directory.")


base_dir = resolve_base_dir()
raw_cve_dir = base_dir / 'data' / 'raw' / 'cve'
output_dir = base_dir / 'data' / 'processed' / 'cve'


def load_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def join_or_default(values):
    if not values:
        return '*'

    return ';'.join(sorted(values))


def extract_cwe(cve):
    cwe_set = set()

    for weakness in cve.get('weaknesses', []):
        for desc in weakness.get('description', []):
            value = desc.get('value', '').strip()
            if value:
                cwe_set.add(value)

    return join_or_default(cwe_set)


def extract_cpe_from_nodes(nodes, cpe_set):
    for node in nodes:
        for match in node.get('cpeMatch', []):
            if match.get('vulnerable') is True:
                cpe_uri = match.get('criteria', '').strip()
                if cpe_uri:
                    cpe_set.add(cpe_uri)

        child_nodes = node.get('nodes', [])
        if child_nodes:
            extract_cpe_from_nodes(child_nodes, cpe_set)


def extract_cpe(cve):
    cpe_set = set()

    for config in cve.get('configurations', []):
        nodes = config.get('nodes', [])
        extract_cpe_from_nodes(nodes, cpe_set)

    return join_or_default(cpe_set)


def parse_cve_item(vuln_item):
    cve = vuln_item.get('cve', {})

    return {
        'cve_id': cve.get('id', '').strip(),
        'matching_cwe': extract_cwe(cve),
        'matching_cpe': extract_cpe(cve)
    }


def process_year(year):
    input_file = raw_cve_dir / f'nvdcve-2.0-{year}.json'
    output_file = output_dir / f'cve_{year}.csv'

    if not input_file.exists():
        print(f'[SKIP] File not found: {input_file}')
        return

    print(f'[INFO] Processing {input_file.name} ...')

    data = load_json(input_file)
    vulnerabilities = data.get('vulnerabilities', [])

    rows = [parse_cve_item(item) for item in vulnerabilities]

    df_cve = pd.DataFrame(rows, columns=['cve_id', 'matching_cwe', 'matching_cpe'])
    df_cve = df_cve.sort_values(by='cve_id').reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    df_cve.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {output_file} ({len(df_cve):,} rows)')


def main():
    for year in range(start_year, end_year + 1):
        process_year(year)


if __name__ == '__main__':
    main()
