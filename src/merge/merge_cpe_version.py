import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
INPUT_FILE = BASE_DIR / 'data' / 'processed' / 'cpe' / 'cpe_dictionary.csv'
OUTPUT_FILE = BASE_DIR / 'data' / 'processed' / 'cpe' / 'cpe_ignore_version.csv'


def main():
    df = pd.read_csv(
        INPUT_FILE,
        usecols=['part', 'vendor', 'product', 'target_sw', 'target_hw']
    ).copy()

    df['versionless_cpe'] = (
        'cpe:' + df['part'].fillna('') + ':' +
        df['vendor'].fillna('') + ':' +
        df['product'].fillna('') + ':' +
        df['target_sw'].fillna('') + ':' +
        df['target_hw'].fillna('')
    )

    df = df.groupby(
        ['part', 'vendor', 'product', 'target_sw', 'target_hw', 'versionless_cpe'],
        as_index=False
    ).size()

    df = df.sort_values(
        by=['size', 'vendor', 'product'],
        ascending=[False, True, True]
    ).reset_index(drop=True)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {OUTPUT_FILE} ({len(df)} rows)')


if __name__ == '__main__':
    main()
