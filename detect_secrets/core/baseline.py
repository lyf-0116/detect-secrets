import json
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from . import upgrades
from ..__version__ import VERSION
from ..exceptions import IncompleteBaselineError
from ..exceptions import UnableToReadBaselineError
from ..settings import configure_settings_from_baseline
from ..settings import get_settings
from ..util.importlib import import_modules_from_package
from ..util.semver import Version
from .scan import get_files_to_scan
from .secrets_collection import SecretsCollection

# Self-describing marker that distinguishes a slim output (a slice of the scanned
# results) from a complete baseline. Absence of this marker means the file is a
# complete baseline, which keeps pre-marker files working unchanged.
SLIM_BASELINE_KEY = 'slim'


def create(
    *paths: str,
    should_scan_all_files: bool = False,
    root: str = '',
    num_processors: Optional[int] = None,
) -> SecretsCollection:
    """Scans all the files recursively in path to initialize a baseline."""
    kwargs = {}
    if num_processors:
        kwargs['num_processors'] = num_processors

    secrets = SecretsCollection(root=root)
    secrets.scan_files(
        *get_files_to_scan(*paths, should_scan_all_files=should_scan_all_files, root=root),
        **kwargs,
    )

    return secrets


def load(
    baseline: Dict[str, Any],
    filename: str = '',
    allow_incomplete: bool = False,
) -> SecretsCollection:
    """
    With a given baseline file, load all settings and discovered secrets from it.

    A slim baseline only carries a slice of the scanned results, so it is not safe to
    use as a complete baseline: doing so would silently drop exclusion records (e.g.
    secrets labelled as false positives) from previous rounds. By default, loading a
    slim baseline is therefore rejected. Callers that can safely operate on a slice
    (e.g. the pre-commit hook, which only diffs against the staged changes) may opt in
    through ``allow_incomplete``.

    :raises: KeyError
    :raises: IncompleteBaselineError
    """
    # This is required for backwards compatibility, and supporting upgrades from older versions.
    baseline = upgrade(baseline)

    if is_slim_baseline(baseline) and not allow_incomplete:
        raise IncompleteBaselineError(filename)

    configure_settings_from_baseline(baseline, filename=filename)
    return SecretsCollection.load_from_baseline(baseline)


def load_from_file(filename: str) -> Dict[str, Any]:
    """
    :raises: UnableToReadBaselineError
    :raises: InvalidBaselineError
    """
    try:
        with open(filename) as f:
            return cast(Dict[str, Any], json.loads(f.read()))
    except (FileNotFoundError, IOError, json.decoder.JSONDecodeError) as e:
        raise UnableToReadBaselineError from e


def format_for_output(secrets: SecretsCollection, is_slim_mode: bool = False) -> Dict[str, Any]:
    output = {
        'version': VERSION,

        # This will populate settings of filters and plugins,
        **get_settings().json(),

        'results': secrets.json(),
    }

    if not is_slim_mode:
        output['generated_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    else:
        # Self-describing marker: a slim output is only a slice of the full results, and
        # must not be accepted as a complete baseline (see `load`).
        output[SLIM_BASELINE_KEY] = True

        # NOTE: This has a nice little side effect of keeping it ordered by line number,
        # even though we don't output it.
        for filename, secret_list in cast(
            Dict[str, List[Dict[str, Any]]],
            output['results'],
        ).items():
            for secret_dict in secret_list:
                secret_dict.pop('line_number')

    return output


def is_slim_baseline(baseline: Dict[str, Any]) -> bool:
    """
    Returns whether the baseline is a self-declared slim (incomplete) output.

    Older baselines never carried this marker, so an absent marker is treated as a
    complete baseline rather than as a corrupt file.
    """
    return bool(baseline.get(SLIM_BASELINE_KEY, False))


def save_to_file(
    secrets: Union[SecretsCollection, Dict[str, Any]],
    filename: str,
) -> None:    # pragma: no cover
    """
    :param secrets: if this is a SecretsCollection, it will output the baseline in its latest
        format. Otherwise, you should pass in a dictionary to this function, to manually
        specify the baseline format to save as.

        If you're trying to decide the difference, ask yourself whether there are any changes
        that does not directly impact the results of the scan.
    """
    # TODO: I wonder whether this should add the `detect_secrets.filters.common.is_baseline_file`
    # filter, since we know the filename already. However, one could argue that it would cause
    # this function to "do more than one thing".
    output = secrets
    if isinstance(secrets, SecretsCollection):
        output = format_for_output(secrets)

    with open(filename, 'w') as f:
        f.write(json.dumps(output, indent=2) + '\n')


def upgrade(baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Baselines will eventually require format changes. This function is responsible for upgrading
    an older baseline to the latest version.
    """
    baseline_version = Version(baseline['version'])
    if baseline_version >= Version(VERSION):
        return baseline

    modules = import_modules_from_package(
        upgrades,
        filter=lambda x: not _is_relevant_upgrade_module(baseline_version)(x),
    )

    new_baseline = {**baseline}
    for module in modules:
        module.upgrade(new_baseline)

    new_baseline['version'] = VERSION
    return new_baseline


def _is_relevant_upgrade_module(current_version: Version) -> Callable:
    def wrapped(module_path: str) -> bool:
        # This converts `v1_0` to `1.0`
        affected_version_string = module_path.rsplit('.', 1)[-1].lstrip('v').replace('_', '.')

        # Patch version doesn't matter, because patches should not require baseline bumps.
        affected_version = Version(f'{affected_version_string}.0')

        return current_version < affected_version

    return wrapped
