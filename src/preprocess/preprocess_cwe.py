import re
import pandas as pd
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.etree.ElementTree import tostring

BASE_DIR = Path(__file__).resolve().parents[2]
RAW_CWE_DIR = BASE_DIR / 'data' / 'raw' / 'cwe'
OUTPUT_DIR = BASE_DIR / 'data' / 'processed' / 'cwe'

INPUT_FILE = RAW_CWE_DIR / 'cwec_v4.19.1.xml'
OUTPUT_FILE = OUTPUT_DIR / 'cwe.csv'

NS = {'cwe': 'http://cwe.mitre.org/cwe-7'}


def clean_text(text):
    if not text:
        return ''

    text = text.replace('\n', ' ').replace('\t', ' ')
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def extract_text(element, tag_name):
    child = element.find(f'cwe:{tag_name}', NS)
    if child is None:
        return ''

    return clean_text(tostring(child, method='text', encoding='unicode'))


def main():
    cols = ['ID', 'Name', 'Description', 'Extended_Description', 'Related_Weakness',
            'Language', 'Technology', 'Likelihood_Of_Exploit', 'Consequence', 'CVE_Example']
    rows = []

    tree = ET.parse(INPUT_FILE)
    root = tree.getroot()

    for item in root.findall('.//cwe:Weakness', NS):
        name = item.attrib.get('Name', '')
        if 'DEPRECATED' in name:
            continue

        cwe_id = f"CWE-{item.attrib.get('ID', '')}"
        description = extract_text(item, 'Description')
        extended_description = extract_text(item, 'Extended_Description')

        related = []
        for rel in item.findall('.//cwe:Related_Weakness', NS):
            nature = rel.attrib.get('Nature', '')
            related_cwe_id = rel.attrib.get('CWE_ID', '')

            if nature and related_cwe_id:
                related.append(f'{nature}:{related_cwe_id}')

        language = []
        for lang in item.findall('.//cwe:Language', NS):
            value = lang.attrib.get('Class') or lang.attrib.get('Name')

            if value and value not in language:
                language.append(value)

        technology = []
        for tech in item.findall('.//cwe:Technology', NS):
            value = tech.attrib.get('Class') or tech.attrib.get('Name')

            if value and value not in technology:
                technology.append(value)

        likelihood = ''
        likelihood_elem = item.find('.//cwe:Likelihood_Of_Exploit', NS)

        if likelihood_elem is not None and likelihood_elem.text:
            likelihood = clean_text(likelihood_elem.text)

        consequence = []
        for cons in item.findall('.//cwe:Common_Consequences/cwe:Consequence', NS):
            for scope in cons.findall('.//cwe:Scope', NS):
                value = clean_text(scope.text)

                if value and value not in consequence:
                    consequence.append(value)

        example = []
        for obs in item.findall('.//cwe:Observed_Examples/cwe:Observed_Example', NS):
            for ref in obs.findall('.//cwe:Reference', NS):
                value = clean_text(ref.text)

                if value and value not in example:
                    example.append(value)

        rows.append({
            'ID': cwe_id,
            'Name': name,
            'Description': description,
            'Extended_Description': extended_description,
            'Related_Weakness': ';'.join(related),
            'Language': ';'.join(language),
            'Technology': ';'.join(technology),
            'Likelihood_Of_Exploit': likelihood,
            'Consequence': ';'.join(consequence),
            'CVE_Example': ';'.join(example)
        })

    df = pd.DataFrame(rows, columns=cols)
    df = df.sort_values(
        by='ID',
        key=lambda s: s.str.extract(r'CWE-(\d+)')[0].astype(int)
    ).reset_index(drop=True)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved: {OUTPUT_FILE} ({len(df)} rows)')


if __name__ == '__main__':
    main()
