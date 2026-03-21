import xml.etree.ElementTree as et
import pandas as pd
from pathlib import Path


def resolve_base_dir():
    current_dir = Path.cwd().resolve()

    for path in [current_dir, *current_dir.parents]:
        if (path / 'data').exists():
            return path

    raise FileNotFoundError("Could not find project root containing 'data' directory.")


base_dir = resolve_base_dir()
raw_cwe_dir = base_dir / 'data' / 'raw' / 'cwe'
output_dir = base_dir / 'data' / 'processed' / 'cwe'

input_file = raw_cwe_dir / 'cwec_v4.19.1.xml'
output_file = output_dir / 'cwe_category.csv'

ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}


def clean_has_member(member_list):
    cleaned_members = []

    for member in member_list:
        if member and member != '*':
            cleaned_members.append(member)

    cleaned_members = sorted(
        set(cleaned_members),
        key=lambda x: int(x.split('-')[1])
    )

    if not cleaned_members:
        return '*'

    return ';'.join(cleaned_members)


def extract_has_member(category):
    member_list = []

    relationships = category.find('cwe:Relationships', ns)
    if relationships is None:
        return '*'

    for has_member in relationships.findall('cwe:Has_Member', ns):
        cwe_id = has_member.attrib.get('CWE_ID', '').strip()

        if cwe_id:
            member_list.append(f'CWE-{cwe_id}')

    return clean_has_member(member_list)


def main():
    rows = []

    tree = et.parse(input_file)
    root = tree.getroot()

    for category in root.findall('.//cwe:Category', ns):
        status = category.attrib.get('Status', '').strip()

        if status == 'Obsolete':
            continue

        category_id = category.attrib.get('ID', '').strip()
        name = category.attrib.get('Name', '').strip()
        has_member = extract_has_member(category)

        if not category_id:
            continue

        if has_member == '*':
            continue

        rows.append({
            'category_id': f'Category-{category_id}',
            'name': name if name else '*',
            'status': status if status else '*',
            'has_member': has_member,
        })

    df = pd.DataFrame(rows, columns=['category_id', 'name', 'status', 'has_member'])

    df = df.sort_values(
        by='category_id',
        key=lambda s: s.str.extract(r'Category-(\d+)')[0].astype(int)
    ).reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {output_file} ({len(df)} rows)')


if __name__ == '__main__':
    main()
