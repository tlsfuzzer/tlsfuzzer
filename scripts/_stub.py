#! /usr/bin/env python
"""An entry-point stub for invoking apps from symlinked scripts."""

import sys
from os import path

REPO_ROOT_DIR = path.dirname(path.dirname(__file__))
sys.path[:0] = [REPO_ROOT_DIR]

normalized_app_importable_base_name = path.splitext(
    path.basename(__file__),
)[0].replace('-', '_')
entry_points_importable_namespace = '.'.join(
    (
        'tlsfuzzer',
        '_apps',
    ),
)
entry_point_importable_path = '.'.join(
    (
        entry_points_importable_namespace,
        normalized_app_importable_base_name,
    ),
)

cli_app_module = __import__(
    entry_point_importable_path,
    fromlist=(entry_points_importable_namespace,),
)

cli_app_module.main()
