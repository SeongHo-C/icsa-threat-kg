import pandas as pd
from pathlib import Path


# Find the project root directory by searching upward for a folder that contains 'data'.
def resolve_base_dir():
    current_dir = Path().cwd().resolve()

    for path in [current_dir, *current_dir.parents]:
        if (path / 'data').exists():
            return path

    raise FileNotFoundError("Could not find project root containing 'data' directory.")


# Define file paths for the input CPE dictionary and the output custom CPE dictionary.
base_dir = resolve_base_dir()
input_file = base_dir / 'data' / 'processed' / 'cpe' / 'cpe_dictionary.csv'
output_file = base_dir / 'data' / 'processed' / 'cpe' / 'custom_cpe_dictionary.csv'


# Normalize a pandas Series by replacing missing or empty values with '*'.
def normalize_series(series):
    return (
        series.astype(object)
        .fillna('*')
        .astype(str)
        .str.strip()
        .replace('', '*')
    )


# Build a custom CPE dictionary by aggregating normalized CPE field combinations.
def main():
    print(f'[INFO] Processing {input_file.name} ...')

    df_cpe = pd.read_csv(
        input_file,
        usecols=['part', 'vendor', 'product', 'target_sw', 'target_hw']
    ).copy()

    df_cpe['part'] = normalize_series(df_cpe['part'])
    df_cpe['vendor'] = normalize_series(df_cpe['vendor'])
    df_cpe['product'] = normalize_series(df_cpe['product'])
    df_cpe['target_sw'] = normalize_series(df_cpe['target_sw'])
    df_cpe['target_hw'] = normalize_series(df_cpe['target_hw'])

    df_cpe['custom_cpe_name'] = (
        'cpe:' + df_cpe['part'] + ':' +
        df_cpe['vendor'] + ':' +
        df_cpe['product'] + ':' +
        df_cpe['target_sw'] + ':' +
        df_cpe['target_hw']
    )

    df_cpe = df_cpe.groupby(
        ['part', 'vendor', 'product', 'target_sw', 'target_hw', 'custom_cpe_name'],
        as_index=False
    ).size().rename(columns={'size': 'count'})

    df_cpe = df_cpe.sort_values(
        by=['count', 'vendor', 'product'],
        ascending=[False, True, True]
    ).reset_index(drop=True)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    df_cpe.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {output_file} ({len(df_cpe):,} rows)')


if __name__ == '__main__':
    main()
