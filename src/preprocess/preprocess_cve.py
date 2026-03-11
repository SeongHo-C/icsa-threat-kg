import json
import pandas as pd
from pathlib import Path

START_YEAR = 2010
END_YEAR = 2026

BASE_DIR = Path(__file__).resolve().parents[2]
RAW_CVE_DIR = BASE_DIR / 'data' / 'raw' / 'cve'
OUTPUT_DIR = BASE_DIR / 'data' / 'processed' / 'cve'


def load_json(file_path):
    with file_path.open('r', encoding='utf-8') as f:
        return json.load(f)


def get_en_description(cve):
    descriptions = cve.get('descriptions', [])

    for item in descriptions:
        if item.get('lang') == 'en':
            return item.get('value', '')

    return descriptions[0].get('value', '') if descriptions else ''


def extract_cwe(cve):
    cwe_set = set()

    for weakness in cve.get('weaknesses', []):
        for desc in weakness.get('description', []):
            value = desc.get('value', '').strip()
            if value:
                cwe_set.add(value)

    return ';'.join(sorted(cwe_set))


def extract_cpe_from_nodes(nodes, cpe_set):
    for node in nodes:
        for match in node.get('cpeMatch', []):
            cpe = match.get('criteria') or match.get('cpe23Uri')
            if cpe:
                cpe_set.add(cpe)

        child_nodes = node.get('nodes', [])
        if child_nodes:
            extract_cpe_from_nodes(child_nodes, cpe_set)


def extract_cpe(cve):
    cpe_set = set()

    for config in cve.get('configurations', []):
        nodes = config.get('nodes', [])
        extract_cpe_from_nodes(nodes, cpe_set)

    return ';'.join(sorted(cpe_set))


def extract_cvss_metrics(cve):
    metrics = cve.get('metrics', {})

    result = {
        'baseSeverity': '',
        'baseScore': '',
        'impactScore': '',
        'exploitabilityScore': '',
        'cvssVector': ''
    }

    for metric_key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        metric_list = metrics.get(metric_key, [])
        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get('cvssData', {})

        result['baseSeverity'] = (
            metric.get('baseSeverity')
            or cvss_data.get('baseSeverity')
            or ''
        )
        result['baseScore'] = cvss_data.get('baseScore', '')
        result['impactScore'] = metric.get('impactScore', '')
        result['exploitabilityScore'] = metric.get('exploitabilityScore', '')
        result['cvssVector'] = cvss_data.get('vectorString', '')

        return result

    return result


def parse_cve_item(vuln_item):
    cve = vuln_item.get('cve', {})

    cve_id = cve.get('id', '')
    description = get_en_description(cve)
    cwe_str = extract_cwe(cve)
    cpe_str = extract_cpe(cve)
    cvss_info = extract_cvss_metrics(cve)

    return {
        'ID': cve_id,
        'MatchingCWE': cwe_str,
        'MatchingCPE': cpe_str,
        'baseSeverity': cvss_info['baseSeverity'],
        'baseScore': cvss_info['baseScore'],
        'impactScore': cvss_info['impactScore'],
        'exploitabilityScore': cvss_info['exploitabilityScore'],
        'cvssVector': cvss_info['cvssVector'],
        'description': description
    }


def process_year(year, raw_dir, output_dir):
    input_file = raw_dir / f'nvdcve-2.0-{year}.json'
    output_file = output_dir / f'cve-{year}.csv'

    if not input_file.exists():
        print(f'[SKIP] File not found: {input_file}')
        return

    print(f'[INFO] Processing {input_file.name} ...')

    data = load_json(input_file)
    vulnerabilities = data.get('vulnerabilities', [])

    rows = [parse_cve_item(item) for item in vulnerabilities]

    columns = ['ID', 'MatchingCWE', 'MatchingCPE', 'baseSeverity', 'baseScore',
               'impactScore', 'exploitabilityScore', 'cvssVector', 'description']

    df = pd.DataFrame(rows, columns=columns)
    df = df.sort_values(by='ID').reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {output_file} ({len(df)} rows)')


def main():
    for year in range(START_YEAR, END_YEAR + 1):
        process_year(year, RAW_CVE_DIR, OUTPUT_DIR)


if __name__ == '__main__':
    main()
