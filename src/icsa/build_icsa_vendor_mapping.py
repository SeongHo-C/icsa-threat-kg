import json
import re
import unicodedata
import pandas as pd
from pathlib import Path
from collections import Counter, defaultdict
from rapidfuzz import fuzz, process

VENDOR_THRESHOLD_HIGH = 95
VENDOR_THRESHOLD_MID = 90
VENDOR_MIN_COUNT_FOR_MID_REVIEW = 2

LEGAL_SUFFIXES = {
    'inc', 'inc.', 'llc', 'ltd', 'ltd.', 'corp', 'corp.', 'corporation',
    'co', 'co.', 'company', 'gmbh', 'ag', 'sa', 'bv', 'plc', 'limited'
}


def resolve_base_dir():
    current_dir = Path.cwd().resolve()

    for path in [current_dir, *current_dir.parents]:
        if (path / 'data').exists():
            return path

    raise FileNotFoundError("Could not find project root containing 'data' directory.")


def safe_json_loads(value):
    if pd.isna(value):
        return []

    text = str(value).strip()
    if not text or text == '*':
        return []

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return []

    if isinstance(loaded, list):
        return loaded

    return []


def extract_raw_vendors(affected_product_value):
    vendors = []

    for item in safe_json_loads(affected_product_value):
        if not isinstance(item, str):
            continue

        if '::' not in item:
            continue

        vendor, _product_name = item.split('::', 1)
        vendor = vendor.strip()

        if vendor:
            vendors.append(vendor)

    return vendors


def normalize_whitespace(text):
    return re.sub(r'\s+', ' ', text).strip()


def normalize_vendor_for_exact(text):
    text = str(text).strip().lower()
    return normalize_whitespace(text)


def normalize_vendor_for_matching(text):
    text = unicodedata.normalize('NFKC', str(text)).lower().strip()

    text = re.sub(r'\([^)]*\)', ' ', text)
    text = text.replace('&', ' and ')
    text = re.sub(r'[/_,\-]+', ' ', text)
    text = re.sub(r'[^\w\s+]', ' ', text, flags=re.UNICODE)

    tokens = []
    for token in text.split():
        if token in LEGAL_SUFFIXES:
            continue
        tokens.append(token)

    normalized = ''.join(tokens)
    return normalized.strip()


def build_unique_mapping(values, normalizer):
    mapping = defaultdict(set)

    for value in values:
        key = normalizer(value)
        if key:
            mapping[key].add(value)

    return mapping


def pick_best_fuzzy_match(raw_vendor, normalized_vendor_to_cpe_vendor):
    query = normalize_vendor_for_matching(raw_vendor)

    if not query:
        return '', 0.0

    choices = list(normalized_vendor_to_cpe_vendor.keys())
    if not choices:
        return '', 0.0

    result = process.extractOne(query, choices, scorer=fuzz.WRatio)
    if result is None:
        return '', 0.0

    matched_key, score, _index = result
    mapped_vendor = normalized_vendor_to_cpe_vendor[matched_key]

    return mapped_vendor, float(score)


def main():
    base_dir = resolve_base_dir()

    processed_icsa_dir = base_dir / 'data' / 'processed' / 'icsa'
    processed_cpe_dir = base_dir / 'data' / 'processed' / 'cpe'

    input_file = processed_icsa_dir / 'cleaned_icsa_dictionary.csv'
    cpe_file = processed_cpe_dir / 'cpe_kg_dictionary.csv'
    output_file = processed_icsa_dir / 'mapping' / 'icsa_vendor_mapping.csv'

    icsa_df = pd.read_csv(input_file)
    cpe_df = pd.read_csv(cpe_file)

    affected_product_column = 'affected_product'
    cpe_vendor_column = 'vendor'

    raw_vendor_counter = Counter()

    for affected_product_value in icsa_df[affected_product_column]:
        vendors = extract_raw_vendors(affected_product_value)
        raw_vendor_counter.update(vendors)

    vendor_count_df = (
        pd.DataFrame(
            [{'raw_vendor': vendor, 'count': count} for vendor, count in raw_vendor_counter.items()]
        )
        .sort_values(['count', 'raw_vendor'], ascending=[False, True])
        .reset_index(drop=True)
    )

    cpe_vendor_values = (cpe_df[cpe_vendor_column].dropna().astype(str).str.strip().tolist())
    cpe_vendor_values = [value for value in cpe_vendor_values if value]

    exact_mapping = build_unique_mapping(cpe_vendor_values, normalize_vendor_for_exact)
    normalized_mapping = build_unique_mapping(cpe_vendor_values, normalize_vendor_for_matching)

    unique_exact_mapping = {
        key: next(iter(values))
        for key, values in exact_mapping.items()
        if len(values) == 1
    }

    unique_normalized_mapping = {
        key: next(iter(values))
        for key, values in normalized_mapping.items()
        if len(values) == 1
    }

    records = []

    for row in vendor_count_df.itertuples(index=False):
        raw_vendor = row.raw_vendor
        count = int(row.count)

        exact_key = normalize_vendor_for_exact(raw_vendor)
        normalized_key = normalize_vendor_for_matching(raw_vendor)

        mapped_vendor = ''
        match_type = 'unmatched'
        match_score = 0.0
        review_decision = 'reject'

        if exact_key in unique_exact_mapping:
            mapped_vendor = unique_exact_mapping[exact_key]
            match_type = 'exact'
            match_score = 100.0
            review_decision = 'accept'
        elif normalized_key in unique_normalized_mapping:
            mapped_vendor = unique_normalized_mapping[normalized_key]
            match_type = 'normalized_exact'
            match_score = 100.0
            review_decision = 'accept'
        else:
            mapped_vendor, match_score = pick_best_fuzzy_match(
                raw_vendor,
                unique_normalized_mapping
            )

            if mapped_vendor:
                match_type = 'fuzzy'

                if match_score >= VENDOR_THRESHOLD_HIGH:
                    review_decision = 'check'
                elif match_score >= VENDOR_THRESHOLD_MID and count >= VENDOR_MIN_COUNT_FOR_MID_REVIEW:
                    review_decision = 'check'
                else:
                    review_decision = 'reject'
            else:
                mapped_vendor = ''
                match_type = 'unmatched'
                match_score = 0.0
                review_decision = 'reject'

        records.append({
            'raw_vendor': raw_vendor,
            'mapped_vendor': mapped_vendor,
            'match_type': match_type,
            'match_score': round(match_score, 6),
            'count': count,
            'review_decision': review_decision,
        })

    output_df = pd.DataFrame(records)

    review_rank = {
        'accept': 0,
        'check': 1,
        'reject': 2,
    }

    match_type_rank = {
        'exact': 0,
        'normalized_exact': 1,
        'fuzzy': 2,
        'unmatched': 3,
    }

    output_df['review_rank'] = output_df['review_decision'].map(review_rank).fillna(9)
    output_df['match_type_rank'] = output_df['match_type'].map(match_type_rank).fillna(9)

    output_df = output_df.sort_values(
        by=['review_rank', 'match_type_rank', 'match_score', 'count', 'raw_vendor'],
        ascending=[True, True, False, False, True]
    ).reset_index(drop=True)

    output_df = output_df.drop(columns=['review_rank', 'match_type_rank'])

    output_df.to_csv(output_file, index=False, encoding='utf-8-sig')

    print(f'[DONE] Saved vendor mapping candidates to: {output_file}')
    print()
    print('[INFO] review_decision counts')
    print(output_df['review_decision'].value_counts(dropna=False).to_string())
    print()
    print('[INFO] match_type counts')
    print(output_df['match_type'].value_counts(dropna=False).to_string())


if __name__ == '__main__':
    main()
