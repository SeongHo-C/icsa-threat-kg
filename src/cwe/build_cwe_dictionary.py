import re
import pandas as pd
import xml.etree.ElementTree as et
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
output_file = output_dir / 'cwe.csv'

ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}

invalid_language_set = {
    'Not Language-Specific',
}

invalid_technology_set = {
    'Not Technology-Specific',
    'Other'
}

invalid_consequence_set = {
    'Other',
}


def clean_text(text):
    if not text:
        return ''

    text = text.replace('\n', ' ').replace('\t', ' ')
    text = re.sub(r'\s+', ' ', text)

    return text.strip()


def join_or_default(values):
    values = [value for value in values if value]

    if not values:
        return '*'

    return ';'.join(sorted(set(values)))


def main():
    columns = [
        'cwe_id',
        'status',
        'related_weakness',
        'language',
        'technology',
        'likelihood_of_exploit',
        'consequence'
    ]
    rows = []
    deprecated_count = 0

    tree = et.parse(input_file)
    root = tree.getroot()

    for item in root.findall('.//cwe:Weakness', ns):
        status = item.attrib.get('Status', '').strip() or '*'
        if status == 'Deprecated':
            deprecated_count += 1
            continue

        cwe_id = f"CWE-{item.attrib.get('ID', '')}"

        related_weakness = []
        for rel in item.findall('.//cwe:Related_Weakness', ns):
            nature = rel.attrib.get('Nature', '').strip()
            related_cwe_id = rel.attrib.get('CWE_ID', '').strip()

            if nature and related_cwe_id:
                related_weakness.append(f'{nature}:{related_cwe_id}')

        language = []
        for lang in item.findall('.//cwe:Language', ns):
            value = (lang.attrib.get('Class') or lang.attrib.get('Name') or '').strip()

            if not value:
                continue

            if value in invalid_language_set:
                continue

            language.append(value)

        technology = []
        for tech in item.findall('.//cwe:Technology', ns):
            value = (tech.attrib.get('Class') or tech.attrib.get('Name') or '').strip()

            if not value:
                continue

            if value in invalid_technology_set:
                continue

            technology.append(value)

        likelihood_of_exploit = '*'
        likelihood_elem = item.find('.//cwe:Likelihood_Of_Exploit', ns)
        if likelihood_elem is not None and likelihood_elem.text:
            likelihood_of_exploit = clean_text(likelihood_elem.text)

        consequence = []
        for cons in item.findall('.//cwe:Common_Consequences/cwe:Consequence', ns):
            for scope in cons.findall('.//cwe:Scope', ns):
                value = clean_text(scope.text)

                if not value:
                    continue

                if value in invalid_consequence_set:
                    continue

                consequence.append(value)

        rows.append({
            'cwe_id': cwe_id,
            'status': status,
            'related_weakness': join_or_default(related_weakness),
            'language': join_or_default(language),
            'technology': join_or_default(technology),
            'likelihood_of_exploit': likelihood_of_exploit,
            'consequence': join_or_default(consequence),
        })

    df_cwe = pd.DataFrame(rows, columns=columns)
    df_cwe = df_cwe.sort_values(
        by='cwe_id',
        key=lambda s: s.str.extract(r'CWE-(\d+)')[0].astype(int)
    ).reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    df_cwe.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[INFO] Removed deprecated CWEs: {deprecated_count:,}')
    print(f'[DONE] Saved: {output_file} ({len(df_cwe):,} rows)')


if __name__ == '__main__':
    main()
