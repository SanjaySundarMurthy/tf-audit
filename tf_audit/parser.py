"""HCL2 parser — reads .tf files into structured TfFile objects."""
import os
import io
from typing import List

import hcl2

from tf_audit.models import TfFile, TfResource


def parse_terraform(path: str) -> List[TfFile]:
    """Parse all .tf files from a path and return TfFile objects."""
    tf_files_paths = _collect_tf_files(path)
    results = []

    for fpath in tf_files_paths:
        tf_file = _parse_file(fpath)
        if tf_file:
            results.append(tf_file)

    return results


def get_all_resources(tf_files: List[TfFile]) -> List[TfResource]:
    """Extract all resources from parsed files."""
    resources = []
    for tf in tf_files:
        resources.extend(tf.resources)
        resources.extend(tf.data_sources)
    return resources


def get_providers(tf_files: List[TfFile]) -> list:
    """Detect which cloud providers are used."""
    providers = set()
    for tf in tf_files:
        for p in tf.providers:
            providers.add(p.get("_name", "unknown"))
        for r in tf.resources:
            provider = r.resource_type.split("_")[0] if "_" in r.resource_type else ""
            if provider in ("aws", "azurerm", "google", "kubernetes", "helm", "null", "random", "local", "tls"):
                providers.add(provider)
    return sorted(providers)


def _collect_tf_files(path: str) -> list:
    """Collect all .tf files from a path."""
    path = os.path.abspath(path)
    if os.path.isfile(path) and path.endswith(".tf"):
        return [path]

    tf_files = []
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            # Skip hidden dirs and .terraform
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != ".terraform"]
            for f in files:
                if f.endswith(".tf") and not f.startswith("."):
                    tf_files.append(os.path.join(root, f))
    return sorted(tf_files)


def _parse_file(filepath: str) -> TfFile:
    """Parse a single .tf file using python-hcl2."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return None

    line_count = content.count("\n") + 1

    try:
        parsed = hcl2.load(io.StringIO(content))
    except Exception:
        # If HCL2 parsing fails, return an empty TfFile
        return TfFile(path=filepath, line_count=line_count)

    tf_file = TfFile(
        path=filepath,
        line_count=line_count,
        raw=parsed,
    )

    # Extract resources
    for res_block in parsed.get("resource", []):
        for res_type, instances in res_block.items():
            for inst in instances if isinstance(instances, list) else [instances]:
                if isinstance(inst, dict):
                    for name, config in inst.items():
                        if isinstance(config, dict):
                            provider = res_type.split("_")[0] if "_" in res_type else ""
                            tf_file.resources.append(TfResource(
                                resource_type=res_type,
                                name=name,
                                provider=provider,
                                config=config,
                                file_path=filepath,
                            ))

    # Extract data sources
    for data_block in parsed.get("data", []):
        for data_type, instances in data_block.items():
            for inst in instances if isinstance(instances, list) else [instances]:
                if isinstance(inst, dict):
                    for name, config in inst.items():
                        if isinstance(config, dict):
                            tf_file.data_sources.append(TfResource(
                                resource_type=f"data.{data_type}",
                                name=name,
                                config=config,
                                file_path=filepath,
                            ))

    # Extract variables
    for var_block in parsed.get("variable", []):
        if isinstance(var_block, dict):
            for var_name, var_config in var_block.items():
                tf_file.variables.append({
                    "_name": var_name,
                    **(var_config if isinstance(var_config, dict) else {}),
                })

    # Extract outputs
    for out_block in parsed.get("output", []):
        if isinstance(out_block, dict):
            for out_name, out_config in out_block.items():
                tf_file.outputs.append({
                    "_name": out_name,
                    **(out_config if isinstance(out_config, dict) else {}),
                })

    # Extract modules
    for mod_block in parsed.get("module", []):
        if isinstance(mod_block, dict):
            for mod_name, mod_config in mod_block.items():
                tf_file.modules.append({
                    "_name": mod_name,
                    **(mod_config if isinstance(mod_config, dict) else {}),
                })

    # Extract providers
    for prov_block in parsed.get("provider", []):
        if isinstance(prov_block, dict):
            for prov_name, prov_config in prov_block.items():
                tf_file.providers.append({
                    "_name": prov_name,
                    **(prov_config if isinstance(prov_config, dict) else {}),
                })

    # Extract terraform blocks
    for tf_block in parsed.get("terraform", []):
        if isinstance(tf_block, dict):
            tf_file.terraform_blocks.append(tf_block)

    # Extract locals
    for loc_block in parsed.get("locals", []):
        if isinstance(loc_block, dict):
            tf_file.locals_blocks.append(loc_block)

    return tf_file
