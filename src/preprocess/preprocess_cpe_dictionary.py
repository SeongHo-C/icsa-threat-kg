import json
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
RAW_CPE_DIR = BASE_DIR / 'data' / 'raw' / 'cpe' / 'nvdcpe-2.0-chunks'
OUTPUT_DIR = BASE_DIR / 'data' / 'processed' / 'cpe'

OUTPUT_FILE = OUTPUT_DIR / 'cpe_dictionary.csv'


def load_json(file_path):
    with file_path.open('r', encoding='utf-8') as f:
        return json.load(f)


def get_title(cpe_item):
    for title in cpe_item.get('titles', []):
        if title.get('lang') == 'en':
            return title.get('title') or title.get('value') or ''

    return ''


def split_cpe23_uri(cpe23_uri):
    parts = cpe23_uri.split(':')

    result = {
        'part': '',
        'vendor': '',
        'product': '',
        'version': '',
        'update': '',
        'edition': '',
        'language': '',
        'sw_edition': '',
        'target_sw': '',
        'target_hw': '',
        'other': ''
    }

    if len(parts) >= 13:
        result['part'] = parts[2]
        result['vendor'] = parts[3]
        result['product'] = parts[4]
        result['version'] = parts[5]
        result['update'] = parts[6]
        result['edition'] = parts[7]
        result['language'] = parts[8]
        result['sw_edition'] = parts[9]
        result['target_sw'] = parts[10]
        result['target_hw'] = parts[11]
        result['other'] = parts[12]

    return result


def parse_cpe_item(cpe_item):
    cpe23_uri = (
        cpe_item.get('cpeName')
        or cpe_item.get('cpe23Uri')
        or cpe_item.get('criteria')
        or ''
    )

    title = get_title(cpe_item)
    cpe_parts = split_cpe23_uri(cpe23_uri)

    return {
        **cpe_parts,
        'cpe23Uri': cpe23_uri,
        'title': title
    }


def extract_cpe_items(data):
    if 'products' in data:
        items = []

        for product in data.get('products', []):
            cpe_item = product.get('cpe', {})
            if cpe_item:
                items.append(cpe_item)

        return items

    if 'cpes' in data:
        return data.get('cpes', [])

    return []


def main():
    cols = ['part', 'vendor', 'product', 'version', 'update', 'edition',
            'language', 'sw_edition', 'target_sw', 'target_hw', 'other',
            'cpe23Uri', 'title']
    rows = []

    for file_path in sorted(RAW_CPE_DIR.glob('*.json')):
        print(f'[INFO] Processing {file_path.name} ...')
        data = load_json(file_path)

        cpe_items = extract_cpe_items(data)
        for cpe_item in cpe_items:
            rows.append(parse_cpe_item(cpe_item))

    df = pd.DataFrame(rows, columns=cols)
    df = df.drop_duplicates().reset_index(drop=True)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {OUTPUT_FILE} ({len(df)} rows)')


if __name__ == '__main__':
    main()
