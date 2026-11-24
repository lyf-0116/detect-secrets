import copy
import multiprocessing as mp
import os
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from . import scan
from ..util.path import convert_local_os_path
from .potential_secret import PotentialSecret
from .potential_secret import UNKNOWN_RULE
from detect_secrets.settings import configure_settings_from_baseline
from detect_secrets.settings import get_settings


class PatchedFile:
    """This exists so that we can do typecasting, without importing unidiff."""
    path: str

    def __iter__(self) -> Generator:
        pass


class SecretsCollection:
    def __init__(self, root: str = '') -> None:
        """
        :param root: if specified, will scan as if the root was the value provided,
            rather than the current working directory. We still store results as if
            relative to root, since we're running as if it was in a different directory,
            rather than scanning a different directory.
        """
        self.data: Dict[str, Set[PotentialSecret]] = defaultdict(set)
        self.root = root

    @classmethod
    def load_from_baseline(cls, baseline: Dict[str, Any]) -> 'SecretsCollection':
        output = cls()
        for filename in baseline['results']:
            for item in baseline['results'][filename]:
                secret = PotentialSecret.load_secret_from_dict({'filename': filename, **item})
                output[convert_local_os_path(filename)].add(secret)

        return output

    @property
    def files(self) -> Set[str]:
        return set(self.data.keys())

    def scan_files(self, *filenames: str, num_processors: Optional[int] = None) -> None:
        """Just like scan_file, but optimized through parallel processing."""
        if len(filenames) == 1:
            self.scan_file(filenames[0])
            return

        if not num_processors:
            num_processors = mp.cpu_count()

        child_process_settings = get_settings().json()

        with mp.Pool(
            processes=num_processors,
            initializer=configure_settings_from_baseline,
            initargs=(child_process_settings,),
        ) as p:
            for secrets in p.imap_unordered(
                _scan_file_and_serialize,
                [os.path.join(self.root, filename) for filename in filenames],
            ):
                for secret in secrets:
                    self[os.path.relpath(secret.filename, self.root)].add(secret)

    def scan_file(self, filename: str) -> None:
        for secret in scan.scan_file(os.path.join(self.root, convert_local_os_path(filename))):
            self[convert_local_os_path(filename)].add(secret)

    def scan_diff(self, diff: str) -> None:
        """
        :raises: UnidiffParseError
        """
        try:
            for secret in scan.scan_diff(diff):
                self[secret.filename].add(secret)
        except ImportError:     # pragma: no cover
            raise NotImplementedError(
                'SecretsCollection.scan_diff requires `unidiff` to work. Try pip '
                'installing that package, and try again.',
            )

    def merge(self, old_results: 'SecretsCollection') -> None:
        """
        We operate under an assumption that the latest results are always more accurate,
        assuming that the baseline is created on the same repository. However, we cannot
        merely discard the old results in favor of the new, since there is valuable information
        that ought to be preserved: verification of secrets, both automated and manual.

        Therefore, this function serves to extract this information from the old results,
        and amend the new results with it.
        """
        for filename in old_results.files:
            if filename not in self.files:
                continue

            # This allows us to obtain the same secret, by accessing the hash.
            mapping = {
                secret: secret
                for secret in self.data[filename]
            }

            for old_secret in old_results.data[filename]:
                if old_secret in mapping:
                    matches = [mapping[old_secret]]
                elif old_secret.rule == UNKNOWN_RULE:
                    # Secrets loaded from older baselines don't know which rule
                    # produced them, so they can't be matched on rule identity.
                    # Fall back to matching on content and plugin (type) alone,
                    # so that manual labels survive the baseline format upgrade.
                    matches = [
                        secret
                        for secret in self.data[filename]
                        if secret.secret_hash == old_secret.secret_hash
                        and secret.type == old_secret.type
                    ]
                else:
                    matches = []

                for secret in matches:
                    # Only override if there's no newer value.
                    if secret.is_secret is None:
                        secret.is_secret = old_secret.is_secret

                    # If the old value is false, it won't make a difference.
                    if not secret.is_verified:
                        secret.is_verified = old_secret.is_verified

    def trim(
        self,
        scanned_results: Optional['SecretsCollection'] = None,
        filelist: Optional[List[str]] = None,
    ) -> None:
        """
        Removes invalid entries in the current SecretsCollection.

        This behaves *kinda* like set intersection and left-join. That is, for matching files,
        a set intersection is performed. For non-matching files, only the files in `self` will
        be kept.

        This is because we may not be constructing the other SecretsCollection with the same
        information as we are with the current SecretsCollection, and we cannot infer based on
        incomplete information. As such, we will keep the status quo.

        Assumptions:
            1. Both `scanned_results` and the current SecretsCollection are constructed using
               the same settings (otherwise, we can't determine whether a missing secret is due
               to newly filtered secrets, or actually removed).

        :param scanned_results: if None, will just clear out non-existent files.
        :param filelist: files without secrets are not present in `scanned_results`. Therefore,
            by supplying this additional filelist, we can assert that if an entry is missing in
            `scanned_results`, it must not have secrets in it.
        """
        if scanned_results is None:
            scanned_results = SecretsCollection()
            filelist = [
                filename
                for filename in self.files
                if not os.path.exists(filename)
            ]

        if not filelist:
            fileset = set()
        else:
            fileset = set(filelist)

        # Unfortunately, we can't merely do a set intersection since we want to update the line
        # numbers (if applicable). Therefore, this does it manually.
        result: Dict[str, Set[PotentialSecret]] = defaultdict(set)

        for filename in scanned_results.files:
            if filename not in self.files:
                continue

            # We construct this so we can get O(1) retrieval of secrets.
            existing_secret_map = {secret: secret for secret in self[filename]}

            # Secrets loaded from older baselines don't know which rule produced
            # them, so index them by content and plugin (type) alone.
            unknown_rule_secrets = {
                (secret.secret_hash, secret.type): secret
                for secret in self[filename]
                if secret.rule == UNKNOWN_RULE
            }
            migrated_secrets: Set[PotentialSecret] = set()

            for secret in scanned_results[filename]:
                existing_secret = existing_secret_map.get(secret)
                if existing_secret is None:
                    legacy_secret = unknown_rule_secrets.get(
                        (secret.secret_hash, secret.type),
                    )
                    if legacy_secret is not None:
                        if legacy_secret not in migrated_secrets:
                            # Migrate the legacy entry to the new format by
                            # adopting the rule reported by the latest scan.
                            legacy_secret.rule = secret.rule
                            migrated_secrets.add(legacy_secret)
                            existing_secret = legacy_secret
                        else:
                            # A single legacy entry can correspond to multiple
                            # rules in the new format. Split it, so that each
                            # rule-level hit retains the labels of the original.
                            existing_secret = copy.copy(legacy_secret)
                            existing_secret.rule = secret.rule

                if existing_secret is None:
                    continue

                # Currently, we assume that the `scanned_results` have no labelled data, so
                # we only want to obtain the latest line number from it.
                if existing_secret.line_number:
                    # Only update line numbers if we're tracking them.
                    existing_secret.line_number = secret.line_number

                result[filename].add(existing_secret)

        for filename in self.files:
            # If this is already populated by scanned_results, then the set intersection
            # is already completed.
            if filename in result:
                continue

            # All secrets relating to that file was removed.
            # We know this because:
            #   1. It's a file that was scanned (in filelist)
            #   2. It would have been in the baseline, if there were secrets...
            #   3. ...but it isn't.
            if filename in fileset:
                continue

            result[filename] = self[filename]

        self.data = result

    def json(self) -> Dict[str, Any]:
        """Custom JSON encoder"""
        output = defaultdict(list)
        for filename, secret in self:
            output[filename].append(secret.json())

        return dict(output)

    def exactly_equals(self, other: Any) -> bool:
        return self.__eq__(other, strict=True)      # type: ignore

    def __getitem__(self, filename: str) -> Set[PotentialSecret]:
        return self.data[filename]

    def __setitem__(self, filename: str, value: Set[PotentialSecret]) -> None:
        self.data[filename] = value

    def __iter__(self) -> Generator[Tuple[str, PotentialSecret], None, None]:
        for filename in sorted(self.files):
            secrets = self[filename]

            # NOTE: If line numbers aren't supplied, they are supposed to default to 0.
            for secret in sorted(
                secrets,
                key=lambda secret: (
                    getattr(secret, 'line_number', 0),
                    secret.secret_hash,
                    secret.type,
                ),
            ):
                yield filename, secret

    def __bool__(self) -> bool:
        # This checks whether there are secrets, rather than just empty files.
        # Empty files can occur with SecretsCollection subtraction.
        return bool(list(self))

    def __eq__(self, other: Any, strict: bool = False) -> bool:
        """
        :param strict: if strict, will return False even if secrets match
            (e.g. if line numbers are different)
        """
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        if self.files != other.files:
            return False

        for filename in self.files:
            self_mapping = {
                (secret.secret_hash, secret.type, secret.rule): secret
                for secret in self[filename]
            }
            other_mapping = {
                (secret.secret_hash, secret.type, secret.rule): secret
                for secret in other[filename]
            }

            # Since PotentialSecret is hashable, we compare their identities through this.
            if set(self_mapping.values()) != set(other_mapping.values()):
                return False

            if not strict:
                continue

            for secretA in self_mapping.values():
                secretB = other_mapping[(secretA.secret_hash, secretA.type, secretA.rule)]

                valuesA = vars(secretA)
                valuesA.pop('secret_value')
                valuesB = vars(secretB)
                valuesB.pop('secret_value')

                if valuesA['line_number'] == 0 or valuesB['line_number'] == 0:
                    # If line numbers are not provided (for either one), then don't compare
                    # line numbers.
                    valuesA.pop('line_number')
                    valuesB.pop('line_number')

                if valuesA != valuesB:
                    return False

        return True

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __sub__(self, other: Any) -> 'SecretsCollection':
        """This behaves like set subtraction."""
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        # We want to create a copy to follow convention and adhere to the principle
        # of least surprise.
        output = SecretsCollection()
        for filename in other.files:
            if filename not in self.files:
                continue

            # Secrets loaded from older baselines don't know which rule produced
            # them, so they cover any scanned secret with matching content and
            # plugin (type), regardless of rule.
            unknown_rule_secrets = {
                (secret.secret_hash, secret.type)
                for secret in other[filename]
                if secret.rule == UNKNOWN_RULE
            }
            output[filename] = {
                secret
                for secret in self[filename]
                if secret not in other[filename]
                and (secret.secret_hash, secret.type) not in unknown_rule_secrets
            }

        for filename in self.files:
            if filename in other.files:
                continue

            output[filename] = self[filename]

        return output

    def __len__(self) -> int:
        """Returns the total number of secrets in the collection."""
        return sum(len(secrets) for secrets in self.data.values())


def _scan_file_and_serialize(filename: str) -> List[PotentialSecret]:
    """Used for multiprocessing, since lambdas can't be serialized."""
    return list(scan.scan_file(filename))
