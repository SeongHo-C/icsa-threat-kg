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

input_dir = base_dir / 'data' / 'processed' / 'cve'
cpe_dict_file = base_dir / 'data' / 'processed' / 'cpe' / 'cpe_kg_dictionary.csv'

output_dir = base_dir / 'data' / 'processed' / 'cve' / 'cleaned'
log_dir = output_dir / 'logs'

invalid_cwe_set = {'NVD-CWE-Other', 'NVD-CWE-noinfo'}


def join_or_default(values):
    if not values:
        return '*'

    return ';'.join(sorted(values))


def load_cpe_candidate_set():
    df_cpe = pd.read_csv(cpe_dict_file, usecols=['kg_cpe'])
    return set(df_cpe['kg_cpe'].dropna().astype(str).str.strip())


def clean_cwe_string(cwe_string):
    if pd.isna(cwe_string) or str(cwe_string).strip() in ['', '*']:
        return '*'

    cwe_set = set()

    for cwe_id in str(cwe_string).split(';'):
        cwe_id = cwe_id.strip()

        if not cwe_id:
            continue

        if cwe_id in invalid_cwe_set:
            continue

        cwe_set.add(cwe_id)

    return join_or_default(cwe_set)


def raw_cpe_to_kg_cpe(raw_cpe):
    raw_cpe = raw_cpe.replace(r'\,', '.').replace(r'\:', ';').replace('"', "'")
    cpe_parts = raw_cpe.split(':')

    if len(cpe_parts) < 13:
        return None

    return ':'.join(['cpe'] + cpe_parts[2:5] + cpe_parts[10:12])


def clean_cpe_string(cve_id, cpe_string, cpe_candidate_set):
    if pd.isna(cpe_string) or str(cpe_string).strip() in ['', '*']:
        return '*', []

    kg_cpe_set = set()
    unmatched_rows = []

    for raw_cpe in str(cpe_string).split(';'):
        raw_cpe = raw_cpe.strip()
        if not raw_cpe:
            continue

        kg_cpe = raw_cpe_to_kg_cpe(raw_cpe)

        if kg_cpe is None:
            unmatched_rows.append({
                'cve_id': cve_id,
                'raw_cpe': raw_cpe,
                'kg_cpe': '*',
                'reason': 'invalid_cpe_format'
            })
            continue

        if kg_cpe not in cpe_candidate_set:
            unmatched_rows.append({
                'cve_id': cve_id,
                'raw_cpe': raw_cpe,
                'kg_cpe': kg_cpe,
                'reason': 'not_in_cpe_kg_dictionary'
            })
            continue

        kg_cpe_set.add(kg_cpe)

    return join_or_default(kg_cpe_set), unmatched_rows


def process_year(year, cpe_candidate_set):
    input_file = input_dir / f'cve_{year}.csv'
    output_file = output_dir / f'cve_{year}.csv'
    unmatched_file = log_dir / f'unmatched_cpe_{year}.csv'

    if not input_file.exists():
        print(f'[SKIP] File not found: {input_file}')
        return

    print(f'[INFO] Processing {input_file.name} ...')

    df_cve = pd.read_csv(input_file).copy()

    required_columns = {'cve_id', 'matching_cwe', 'matching_cpe'}
    if not required_columns.issubset(df_cve.columns):
        raise ValueError(
            f'Missing required columns in {input_file.name}: '
            f'{sorted(required_columns - set(df_cve.columns))}'
        )

    total_rows_before = len(df_cve)
    unmatched_rows_all = []

    cleaned_cwe_list = []
    cleaned_cpe_list = []

    for _, row in df_cve.iterrows():
        cleaned_cwe = clean_cwe_string(row['matching_cwe'])
        cleaned_cpe, unmatched_rows = clean_cpe_string(row['cve_id'], row['matching_cpe'], cpe_candidate_set)

        cleaned_cwe_list.append(cleaned_cwe)
        cleaned_cpe_list.append(cleaned_cpe)
        unmatched_rows_all.extend(unmatched_rows)

    df_cve['matching_cwe'] = cleaned_cwe_list
    df_cve['matching_cpe'] = cleaned_cpe_list

    df_cve = df_cve[~((df_cve['matching_cwe'] == '*') & (df_cve['matching_cpe'] == '*'))].copy()
    df_cve = df_cve.sort_values(by='cve_id').reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    df_cve.to_csv(output_file, index=False, encoding='utf-8-sig')

    df_unmatched = pd.DataFrame(
        unmatched_rows_all,
        columns=['cve_id', 'raw_cpe', 'kg_cpe', 'reason']
    )
    df_unmatched.to_csv(unmatched_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved cleaned CVE file: {output_file} ({len(df_cve):,} rows)')
    print(f'[DONE] Saved unmatched CPE log: {unmatched_file} ({len(df_unmatched):,} rows)')
    print(f'[INFO] Removed empty CVE rows: {total_rows_before - len(df_cve):,}')


def main():
    print(f'[INFO] Loading {cpe_dict_file.name} ...')
    cpe_candidate_set = load_cpe_candidate_set()
    print(f'[DONE] Loaded KG CPE candidates: {len(cpe_candidate_set):,}')

    for year in range(start_year, end_year + 1):
        process_year(year, cpe_candidate_set)


if __name__ == '__main__':
    main()
