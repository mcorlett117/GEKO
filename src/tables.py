from opencti import get_actor_techniques, get_techniques_ids, get_sigma_rules_for_technique
import os
from log import log_debug
from dotenv import load_dotenv

# ==============
# Config
# ==============
load_dotenv()
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
OPENCTI_HEADERS = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type": "application/json"
}


# ==============
# Make tables
# ==============

def create_actor_table(OPENCTI_URL, OPENCTI_HEADERS, all_actors, TABLE_LENGTH):
    actor_rows = []
    for actor_id, actor_name, actor_aliases in all_actors:
        if not isinstance(actor_aliases, list):
            actor_aliases = []
        techniques = get_actor_techniques(OPENCTI_URL, OPENCTI_HEADERS, actor_id)
        if not techniques:
            log_debug(f"No techniques found for actor: {actor_name}")
            continue
        attack_pattern_count = len(techniques) if techniques else 0
        actor_rows.append({
            "name": actor_name,
            "aliases": ', '.join(actor_aliases),
            "attack_patterns": attack_pattern_count
        })
    sorted_actors = sorted(actor_rows, key=lambda x: x["attack_patterns"], reverse=True)[:TABLE_LENGTH]
    table_lines = []
    for actor in sorted_actors:
        table_lines.append(f"| {actor['name']} | {actor['aliases']} | {actor['attack_patterns']} |")
    return '\n'.join(table_lines)


def create_technique_table(OPENCTI_URL, OPENCTI_HEADERS, all_actors, TABLE_LENGTH):
    # Create a dictionary to count technique usage
    technique_counts = {}
    for actor_id, actor_name, actor_aliases in all_actors:
        techniques = get_actor_techniques(OPENCTI_URL, OPENCTI_HEADERS, actor_id)
        if techniques:
            for tech in techniques:
                tid = tech.get("x_mitre_id")
                technique_name = tech.get("name")
                if tid not in technique_counts:
                    technique_counts[tid] = {
                        "tid": tid,
                        "name": technique_name,
                        "actors": set()
                    }
                technique_counts[tid]["actors"].add(actor_name)
    
    # Now, count is the number of unique actors for each technique
    for tid in technique_counts:
        technique_counts[tid]["count"] = len(technique_counts[tid]["actors"])

    sorted_techniques = sorted(technique_counts.values(), key=lambda x: x["count"], reverse=True)[:TABLE_LENGTH]

    table_lines = []
    for tech in sorted_techniques:
        table_lines.append(f"| {tech['tid']} {tech['name']} | {', '.join(tech['actors'])} | {tech['count']} |")
    return '\n'.join(table_lines)


def create_coverage_table(unique_techniques, elastic_techniques, sigma_techniques, TABLE_LENGTH):
    # count the number of rules for each technique
    coverage_rows = []
    for technique in unique_techniques:
        tid = technique.get('x_mitre_id')
        technique_name = technique.get('name', 'Unknown Technique')

        # Collect unique Elastic rule names that cover this technique (by tid or stid)
        elastic_rule_names = set( et['rule'] for et in elastic_techniques if et['tid'] == tid or et.get('stid') == tid )
        elastic_count = len(elastic_rule_names)

        # Collect unique Sigma rule names that cover this technique (by tid)
        sigma_rule_names = set( st['rule'] for st in sigma_techniques if st['tid'] == tid )
        sigma_count = len(sigma_rule_names)

        covered = "NO" if elastic_count == 0 else "YES"

        coverage_rows.append({
            "technique_id": tid,
            "technique_name": technique_name,
            "elastic": elastic_count,
            "sigma": sigma_count,
            "covered": covered 
        })

    
    sorted_covered = sorted(coverage_rows, key=lambda x: (-x["elastic"], -x["sigma"]))
    table_cover = []
    for row in sorted_covered[:TABLE_LENGTH]:
        table_cover.append(f"| {row['technique_id']} {row['technique_name']} | {row['elastic']} | {row['sigma']} | {row['covered']} |")
    cover_table = '\n'.join(table_cover)

    sorted_uncovered = sorted(coverage_rows, key=lambda x: (x["elastic"], x["sigma"]))
    table_uncovered = []
    for row in sorted_uncovered[:TABLE_LENGTH]:
        table_uncovered.append(f"| {row['technique_id']} {row['technique_name']} | {row['elastic']} | {row['sigma']} | {row['covered']} |")
    uncovered_table = '\n'.join(table_uncovered)

    uncovered_rows = [row for row in coverage_rows if row["covered"] == "NO"]
    sorted_uncovered_rows = sorted(uncovered_rows, key=lambda x: -x["sigma"])
    table_sigma = []
    for row in sorted_uncovered_rows[:TABLE_LENGTH]:
        tech_id = get_techniques_ids(OPENCTI_URL, OPENCTI_HEADERS, row['technique_id'])
        sigma_rules, sigmatotal = get_sigma_rules_for_technique(OPENCTI_URL, OPENCTI_HEADERS, tech_id)
        fivesigma = []
        for indicator_id, indicator_name in sigma_rules[:5]:
            fivesigma.append((indicator_id, indicator_name))
        table_sigma.append(f"| {row['technique_id']} {row['technique_name']} | {row['sigma']} | {row['elastic']} | {fivesigma} |")
    sigma_table = '\n'.join(table_sigma)

    return cover_table, uncovered_table, sigma_table


def create_metric_table(elastic_techniques, sigma_techniques, unique_techniques):
    total_techniques = len(unique_techniques)
    unique_tids = set(t.get('x_mitre_id') for t in unique_techniques)

    covered_by_elastic = sum( any( et['tid'] == tid or et.get('stid') == tid for et in elastic_techniques ) for tid in unique_tids )

    covered_by_sigma = sum( any( st['tid'] == tid for st in sigma_techniques ) for tid in unique_tids  )

    uncovered = total_techniques - len(set( tid for tid in unique_tids if any(et['tid'] == tid or et.get('stid') == tid for et in elastic_techniques) or any(st['tid'] == tid for st in sigma_techniques)))

    metric_table = f"""| Total Techniques | {total_techniques} | 100% |
| Covered by Elastic | {covered_by_elastic} | {covered_by_elastic / total_techniques * 100:.2f}% |
| Covered by Sigma | {covered_by_sigma} | {covered_by_sigma / total_techniques * 100:.2f}% |
| Uncovered | {uncovered} | {uncovered / total_techniques * 100:.2f}% |
"""
    return metric_table


