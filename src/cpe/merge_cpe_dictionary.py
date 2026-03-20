import pandas as pd
from pathlib import Path


def resolve_base_dir():
    current_dir = Path().cwd().resolve()

    for path in [current_dir, *current_dir.parents]:
        if (path / 'data').exists():
            return path

    raise FileNotFoundError("Could not find project root containing 'data' directory.")


base_dir = resolve_base_dir()
input_file = base_dir / 'data' / 'processed' / 'cpe' / 'cpe_dictionary.csv'
output_file = base_dir / 'data' / 'processed' / 'cpe' / 'cpe_kg_dictionary.csv'


def normalize_field(series):
    return (series.astype(object).fillna('*').astype(str).str.strip().replace('', '*'))


def main():
    print(f'[INFO] Processing {input_file.name} ...')

    df_cpe = pd.read_csv(
        input_file,
        usecols=['part', 'vendor', 'product', 'target_sw', 'target_hw']
    ).copy()

    df_cpe['part'] = normalize_field(df_cpe['part'])
    df_cpe['vendor'] = normalize_field(df_cpe['vendor'])
    df_cpe['product'] = normalize_field(df_cpe['product'])
    df_cpe['target_sw'] = normalize_field(df_cpe['target_sw'])
    df_cpe['target_hw'] = normalize_field(df_cpe['target_hw'])

    df_cpe['kg_cpe'] = (
        'cpe:' + df_cpe['part'] + ':' +
        df_cpe['vendor'] + ':' +
        df_cpe['product'] + ':' +
        df_cpe['target_sw'] + ':' +
        df_cpe['target_hw']
    )

    df_cpe = df_cpe.groupby(
        ['part', 'vendor', 'product', 'target_sw', 'target_hw', 'kg_cpe'],
        as_index=False
    ).size()

    # Sort merged CPEs by frequency, then by vendor and product name.
    df_cpe = df_cpe.sort_values(
        by=['size', 'vendor', 'product'],
        ascending=[False, True, True]
    ).reset_index(drop=True)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    df_cpe.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {output_file} ({len(df_cpe):,} rows)')


if __name__ == '__main__':
    main()
