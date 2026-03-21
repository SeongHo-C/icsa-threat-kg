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

processed_icsa_dir = base_dir / 'data' / 'processed' / 'icsa'
processed_cve_dir = base_dir / 'data' / 'processed' / 'cve' / 'cleaned'

input_file = processed_icsa_dir / 'icsa_dictionary.csv'
output_file = processed_icsa_dir / 'cleaned_icsa_dictionary.csv'
unmatched_cve_file = processed_icsa_dir / 'unmatched_icsa_cve.csv'
invalid_product_file = processed_icsa_dir / 'invalid_affected_product.csv'
removed_advisory_file = processed_icsa_dir / 'removed_icsa_advisory.csv'

target_years = list(range(2016, 2026))
cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
separator = ';'
product_separator = '::'


def clean_text(text):
    if text is None:
        return None

    text = str(text).strip()
    text = re.sub(r'\s+', ' ', text)

    return text if text else None


def parse_icsa_sort_key(advisory_id):
    if not isinstance(advisory_id, str):
        return (9999, 9999, 9999)

    match = re.match(r'^ICSA-(\d{2})-(\d+)-(\d+)$', advisory_id)
    if match:
        year, advisory_num, sub_num = match.groups()
        return (int(year), int(advisory_num), int(sub_num))

    return (9999, 9999, 9999)


def load_valid_cve_set():
    valid_cve_set = set()

    for year in target_years:
        cve_file = processed_cve_dir / f'cve_{year}.csv'

        if not cve_file.exists():
            print(f'[WARN] CVE file not found: {cve_file}')
            continue

        df = pd.read_csv(cve_file)

        if 'cve_id' not in df.columns:
            print(f'[WARN] Missing cve_id column: {cve_file}')
            continue

        cve_ids = df['cve_id'].dropna().astype(str).str.strip().tolist()
        valid_cve_set.update(cve_ids)

    print(f'[INFO] Loaded {len(valid_cve_set)} valid CVE IDs')
    return valid_cve_set


def split_cve_value(text):
    text = clean_text(text)

    if not text or text == '*':
        return []

    values = []

    for item in text.split(separator):
        item = clean_text(item)
        if item:
            values.append(item)

    return values


def split_affected_product_value(text):
    text = clean_text(text)

    if not text or text == '*':
        return []

    try:
        values = json.loads(text)
    except json.JSONDecodeError:
        return ['__INVALID_JSON__']

    if not isinstance(values, list):
        return ['__INVALID_JSON__']

    cleaned_values = []

    for item in values:
        item = clean_text(item)
        if item:
            cleaned_values.append(item)

    return cleaned_values


def clean_cve_field(advisory_id, cve_text, valid_cve_set):
    raw_cves = split_cve_value(cve_text)

    cleaned_cves = []
    log_rows = []

    for raw_cve in raw_cves:
        cve_id = clean_text(raw_cve)

        if not cve_id:
            continue

        if not cve_pattern.match(cve_id):
            log_rows.append({
                'advisory_id': advisory_id,
                'raw_cve': raw_cve,
                'reason': 'invalid_format',
            })
            continue

        if cve_id not in valid_cve_set:
            log_rows.append({
                'advisory_id': advisory_id,
                'raw_cve': raw_cve,
                'reason': 'not_in_cleaned_cve',
            })
            continue

        cleaned_cves.append(cve_id)

    cleaned_cves = sorted(set(cleaned_cves))

    if not cleaned_cves:
        return '*', log_rows

    return separator.join(cleaned_cves), log_rows


def clean_affected_product_field(advisory_id, affected_product_text):
    raw_products = split_affected_product_value(affected_product_text)

    cleaned_products = []
    log_rows = []

    if raw_products == ['__INVALID_JSON__']:
        log_rows.append({
            'advisory_id': advisory_id,
            'raw_product': affected_product_text,
            'reason': 'invalid_json_format',
        })
        return '*', log_rows

    for raw_product in raw_products:
        product_text = clean_text(raw_product)

        if not product_text:
            continue

        if product_separator not in product_text:
            log_rows.append({
                'advisory_id': advisory_id,
                'raw_product': raw_product,
                'reason': 'missing_separator',
            })
            continue

        vendor, product_name = product_text.split(product_separator, 1)
        vendor = clean_text(vendor)
        product_name = clean_text(product_name)

        if not vendor:
            log_rows.append({
                'advisory_id': advisory_id,
                'raw_product': raw_product,
                'reason': 'empty_vendor',
            })
            continue

        if not product_name:
            log_rows.append({
                'advisory_id': advisory_id,
                'raw_product': raw_product,
                'reason': 'empty_product_name',
            })
            continue

        cleaned_products.append(f'{vendor}{product_separator}{product_name}')

    cleaned_products = sorted(set(cleaned_products), key=lambda x: x.lower())

    if not cleaned_products:
        return '*', log_rows

    return json.dumps(cleaned_products, ensure_ascii=False), log_rows


def main():
    if not input_file.exists():
        raise FileNotFoundError(f'Input file not found: {input_file}')

    valid_cve_set = load_valid_cve_set()

    df = pd.read_csv(input_file).fillna('*')

    required_columns = {'advisory_id', 'name', 'cve', 'affected_product'}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(f'Missing required columns: {sorted(missing_columns)}')

    df = df[['advisory_id', 'name', 'cve', 'affected_product']].copy()

    cleaned_rows = []
    unmatched_cve_logs = []
    invalid_product_logs = []
    removed_advisory_logs = []

    for _, row in df.iterrows():
        advisory_id = clean_text(row['advisory_id'])
        name = clean_text(row['name']) or '*'

        if not advisory_id:
            removed_advisory_logs.append({
                'advisory_id': '*',
                'reason': 'missing_advisory_id',
            })
            continue

        cleaned_cve, cve_logs = clean_cve_field(advisory_id, row['cve'], valid_cve_set)
        cleaned_product, product_logs = clean_affected_product_field(advisory_id, row['affected_product'])

        unmatched_cve_logs.extend(cve_logs)
        invalid_product_logs.extend(product_logs)

        if cleaned_cve == '*' and cleaned_product == '*':
            removed_advisory_logs.append({
                'advisory_id': advisory_id,
                'reason': 'empty_cve_and_affected_product',
            })
            continue

        if cleaned_cve == '*':
            removed_advisory_logs.append({
                'advisory_id': advisory_id,
                'reason': 'empty_cve_after_cleaning',
            })
            continue

        if cleaned_product == '*':
            removed_advisory_logs.append({
                'advisory_id': advisory_id,
                'reason': 'empty_affected_product_after_cleaning',
            })
            continue

        cleaned_rows.append({
            'advisory_id': advisory_id,
            'name': name,
            'cve': cleaned_cve,
            'affected_product': cleaned_product,
        })

    cleaned_df = pd.DataFrame(
        cleaned_rows,
        columns=['advisory_id', 'name', 'cve', 'affected_product']
    )

    if not cleaned_df.empty:
        cleaned_df = cleaned_df.sort_values(
            by='advisory_id',
            key=lambda s: s.map(parse_icsa_sort_key)
        ).reset_index(drop=True)

    processed_icsa_dir.mkdir(parents=True, exist_ok=True)

    cleaned_df.to_csv(output_file, index=False, encoding='utf-8-sig')
    print(f'[DONE] Saved: {output_file} ({len(cleaned_df)} rows)')

    unmatched_cve_df = pd.DataFrame(unmatched_cve_logs, columns=['advisory_id', 'raw_cve', 'reason'])
    unmatched_cve_df.to_csv(unmatched_cve_file, index=False, encoding='utf-8-sig')
    print(f'[INFO] Saved: {unmatched_cve_file} ({len(unmatched_cve_df)} rows)')

    invalid_product_df = pd.DataFrame(invalid_product_logs, columns=['advisory_id', 'raw_product', 'reason'])
    invalid_product_df.to_csv(invalid_product_file, index=False, encoding='utf-8-sig')
    print(f'[INFO] Saved: {invalid_product_file} ({len(invalid_product_df)} rows)')

    removed_advisory_df = pd.DataFrame(removed_advisory_logs, columns=['advisory_id', 'reason'])
    removed_advisory_df.to_csv(removed_advisory_file, index=False, encoding='utf-8-sig')
    print(f'[INFO] Saved: {removed_advisory_file} ({len(removed_advisory_df)} rows)')


if __name__ == '__main__':
    main()
