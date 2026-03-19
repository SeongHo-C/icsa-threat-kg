import json
import pandas as pd
from pathlib import Path


def resolve_base_dir():
    current_dir = Path.cwd().resolve()

    for path in [current_dir, *current_dir.parents]:
        if (path / 'data').exists():
            return path

    raise FileNotFoundError("Could not find project root containing 'data' directory.")


base_dir = resolve_base_dir()
raw_cpe_dir = base_dir / 'data' / 'raw' / 'cpe' / 'nvdcpe-2.0-chunks'
output_dir = base_dir / 'data' / 'processed' / 'cpe'
output_file = output_dir / 'cpe_dictionary.csv'

columns = ['part', 'vendor', 'product', 'target_sw', 'target_hw', 'cpe23_uri']


def load_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def normalize_field(value):
    if value is None:
        return '*'

    value = str(value).strip()
    return value if value else '*'


def split_cpe23_uri(cpe23_uri):
    parts = cpe23_uri.split(':')
    result = {'part': '*', 'vendor': '*', 'product': '*', 'target_sw': '*', 'target_hw': '*'}

    if len(parts) >= 13:
        result['part'] = normalize_field(parts[2])
        result['vendor'] = normalize_field(parts[3])
        result['product'] = normalize_field(parts[4])
        result['target_sw'] = normalize_field(parts[10])
        result['target_hw'] = normalize_field(parts[11])

    return result


def parse_cpe_item(cpe_item):
    cpe23_uri = cpe_item.get('cpeName', '')
    cpe_parts = split_cpe23_uri(cpe23_uri)

    return {**cpe_parts, 'cpe23_uri': cpe23_uri}


def extract_cpe_items(data):
    items = []

    for product in data.get('products', []):
        cpe_item = product.get('cpe', {})
        if cpe_item:
            items.append(cpe_item)

    return items


def main():
    rows = []

    json_files = sorted(raw_cpe_dir.glob('*.json'))
    if not json_files:
        raise FileNotFoundError(f'No JSON files found in: {raw_cpe_dir}')

    for file_path in json_files:
        print(f'[INFO] Processing {file_path.name} ...')
        data = load_json(file_path)

        cpe_items = extract_cpe_items(data)
        for cpe_item in cpe_items:
            rows.append(parse_cpe_item(cpe_item))

    df_cpe = pd.DataFrame(rows, columns=columns)
    # Remove duplicate CPE rows and reset the row index.
    df_cpe = df_cpe.drop_duplicates().reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    df_cpe.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {output_file} ({len(df_cpe):,} rows)')


if __name__ == '__main__':
    main()
