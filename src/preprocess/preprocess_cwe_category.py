import xml.etree.ElementTree as ET
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
RAW_CWE_DIR = BASE_DIR / 'data' / 'raw' / 'cwe'
OUTPUT_DIR = BASE_DIR / 'data' / 'processed' / 'cwe'

INPUT_FILE = RAW_CWE_DIR / 'cwec_v4.19.1.xml'
OUTPUT_FILE = OUTPUT_DIR / 'cwe_category.csv'

NS = {'cwe': 'http://cwe.mitre.org/cwe-7'}


def main():
    cols = ['ID', 'Name', 'Status', 'Has_Member']
    rows = []

    tree = ET.parse(INPUT_FILE)
    root = tree.getroot()

    for item in root.findall('.//cwe:Category', NS):
        status = item.attrib.get('Status', '')
        if 'Deprecated' in status:
            continue

        category_id = f"Category-{item.attrib.get('ID', '')}"
        name = item.attrib.get('Name', '')

        has_member = []
        for relationships in item.findall('.//cwe:Relationships', NS):
            for member in relationships.findall('.//cwe:Has_Member', NS):
                member_id = member.attrib.get('CWE_ID', '')
                if member_id:
                    has_member.append(f'CWE-{member_id}')

        rows.append({
            'ID': category_id,
            'Name': name,
            'Status': status,
            'Has_Member': ';'.join(has_member)
        })

    df = pd.DataFrame(rows, columns=cols)
    df = df.sort_values(
        by='ID',
        key=lambda s: s.str.extract(r'Category-(\d+)')[0].astype(int)
    ).reset_index(drop=True)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {OUTPUT_FILE} ({len(df)} rows)')


if __name__ == '__main__':
    main()
