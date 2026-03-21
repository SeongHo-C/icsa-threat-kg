import json
import re
import pandas as pd
from pathlib import Path


def resolve_base_dir():
    current_dir = Path.cwd().resolve()

    for path in [current_dir, *current_dir.parents]:
        if (path / 'data').exists():
            return path

    raise FileNotFoundError("Could not find project root containing 'data' directory.")


base_dir = resolve_base_dir()
raw_icsa_dir = base_dir / 'data' / 'raw' / 'icsa'
output_dir = base_dir / 'data' / 'processed' / 'icsa'

output_file = output_dir / 'icsa_dictionary.csv'

target_years = list(range(2016, 2026))


def clean_text(text):
    if text is None:
        return None

    text = str(text).strip()
    text = re.sub(r'\s+', ' ', text)

    return text if text else None


def clean_cve_list(cve_list):
    cleaned_cves = []

    for cve in cve_list:
        cve = clean_text(cve)

        if cve:
            cleaned_cves.append(cve)

    cleaned_cves = sorted(set(cleaned_cves))

    if not cleaned_cves:
        return '*'

    return ';'.join(cleaned_cves)


def clean_affected_product_list(affected_product_list):
    cleaned_products = []

    for item in affected_product_list:
        item = clean_text(item)
        if item:
            cleaned_products.append(item)

    cleaned_products = sorted(set(cleaned_products), key=lambda x: x.lower())

    if not cleaned_products:
        return '*'

    return json.dumps(cleaned_products, ensure_ascii=False)


def parse_icsa_sort_key(advisory_id):
    if not isinstance(advisory_id, str):
        return (9999, 9999, 9999)

    match = re.match(r'^ICSA-(\d{2})-(\d+)-(\d+)$', advisory_id)
    if match:
        year, advisory_num, sub_num = match.groups()
        return (int(year), int(advisory_num), int(sub_num))

    return (9999, 9999, 9999)


def build_product_map(product_tree):
    product_map = {}

    def traverse(node, vendor=None, product_name=None):
        if not isinstance(node, dict):
            return

        current_vendor = vendor
        current_product_name = product_name

        node_name = clean_text(node.get('name'))
        node_category = node.get('category')

        if node_category == 'vendor':
            current_vendor = node_name
        elif node_category == 'product_name':
            current_product_name = node_name

        product = node.get('product')
        if isinstance(product, dict):
            product_id = clean_text(product.get('product_id'))

            if product_id:
                product_map[product_id] = {
                    'vendor': current_vendor,
                    'product_name': current_product_name
                }

        for child in node.get('branches', []):
            traverse(child, current_vendor, current_product_name)

    for branch in product_tree.get('branches', []):
        traverse(branch)

    return product_map


def extract_name(data):
    document = data.get('document', {})
    title = clean_text(document.get('title'))

    if title:
        return title

    return '*'


def extract_cve_list(data):
    cve_list = []

    for vulnerability in data.get('vulnerabilities', []):
        cve_id = clean_text(vulnerability.get('cve'))

        if cve_id:
            cve_list.append(cve_id)

    return clean_cve_list(cve_list)


def extract_affected_product_list(data, product_map):
    affected_product_list = []

    for vulnerability in data.get('vulnerabilities', []):
        product_status = vulnerability.get('product_status', {})

        for product_id in product_status.get('known_affected', []):
            product_id = clean_text(product_id)

            if not product_id:
                continue

            product_info = product_map.get(product_id, {})
            vendor = clean_text(product_info.get('vendor'))
            product_name = clean_text(product_info.get('product_name'))

            if not vendor or not product_name:
                continue

            affected_product_list.append(f'{vendor}::{product_name}')

    return clean_affected_product_list(affected_product_list)


def extract_icsa_record(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    document = data.get('document', {})
    tracking = document.get('tracking', {})
    advisory_id = clean_text(tracking.get('id'))

    if not advisory_id:
        return None

    product_tree = data.get('product_tree', {})
    product_map = build_product_map(product_tree)

    name = extract_name(data)
    cve = extract_cve_list(data)
    affected_product = extract_affected_product_list(data, product_map)

    if cve == '*' and affected_product == '*':
        return None

    return {
        'advisory_id': advisory_id,
        'name': name,
        'cve': cve,
        'affected_product': affected_product,
    }


def main():
    rows = []
    failed_files = []

    year_dirs = [
        raw_icsa_dir / str(year)
        for year in target_years
        if (raw_icsa_dir / str(year)).exists()
    ]

    for year_dir in year_dirs:
        json_files = sorted(year_dir.glob('icsa-*.json'))
        print(f'[INFO] Year {year_dir.name}: {len(json_files)} files found')

        for json_file in json_files:
            try:
                record = extract_icsa_record(json_file)

                if record is not None:
                    rows.append(record)

            except Exception as e:
                failed_files.append({
                    'year': year_dir.name,
                    'file_name': json_file.name,
                    'error': str(e),
                })
                print(f'[ERROR] Failed to parse {json_file.name}: {e}')

    df = pd.DataFrame(rows, columns=['advisory_id', 'name', 'cve', 'affected_product'])

    if not df.empty:
        df = df.drop_duplicates(subset=['advisory_id']).copy()

        df = df.sort_values(
            by='advisory_id',
            key=lambda s: s.map(parse_icsa_sort_key)
        ).reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'\n[DONE] Saved: {output_file} ({len(df)} rows)')

    if failed_files:
        failed_df = pd.DataFrame(failed_files)
        failed_output_file = output_dir / 'failed_icsa_files.csv'
        failed_df.to_csv(failed_output_file, index=False, encoding='utf-8-sig')
        print(f'[INFO] Failed files log saved: {failed_output_file} ({len(failed_df)} rows)')


if __name__ == '__main__':
    main()
