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
from detect_secrets.settings import configure_settings_from_baseline
from detect_secrets.settings import get_settings


# Human labels (e.g. `is_secret`) are judgements that a person made about a finding.
# They outlive the results they were originally attached to: results are regenerated
# on every scan, and their shape may change across versions (e.g. a detector is
# renamed), but the judgement about the underlying content still stands. To honour
# that longer lifecycle, labels are re-attached by content features and path alone
# (see `SecretsCollection.merge`), rather than by version-specific attributes such
# as the detector type.
#
# The trade-off is that identical content appearing in multiple places of the same
# file inherits the same label. To limit the blast radius of this content-based
# matching, it only applies to secrets whose content is long enough to be
# considered distinctive.
MIN_CONTENT_LENGTH_FOR_LABEL_MATCH = 8


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

        Matching is done in two passes: first by exact result identity (which includes
        the detector type), then by content and path alone. The second pass decouples
        human labels from version-specific attributes, so they still attach when a
        detector is renamed or repositioned between versions -- at the cost of
        labelling all identical content in the same file alike (see
        MIN_CONTENT_LENGTH_FOR_LABEL_MATCH).
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
                if old_secret not in mapping:
                    continue

                # Only override if there's no newer value.
                if mapping[old_secret].is_secret is None:
                    mapping[old_secret].is_secret = old_secret.is_secret

                # If the old value is false, it won't make a difference.
                if not mapping[old_secret].is_verified:
                    mapping[old_secret].is_verified = old_secret.is_verified

            _inherit_labels_by_content(
                old_secrets=old_results.data[filename],
                new_secrets=self.data[filename],
            )

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
            for secret in scanned_results[filename]:
                if secret not in existing_secret_map:
                    continue

                # Currently, we assume that the `scanned_results` have no labelled data, so
                # we only want to obtain the latest line number from it.
                existing_secret = existing_secret_map[secret]
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
                (secret.secret_hash, secret.type): secret for secret in self[filename]
            }
            other_mapping = {
                (secret.secret_hash, secret.type): secret for secret in other[filename]
            }

            # Since PotentialSecret is hashable, we compare their identities through this.
            if set(self_mapping.values()) != set(other_mapping.values()):
                return False

            if not strict:
                continue

            for secretA in self_mapping.values():
                secretB = other_mapping[(secretA.secret_hash, secretA.type)]

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

            output[filename] = self[filename] - other[filename]

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


def _inherit_labels_by_content(
    old_secrets: Set[PotentialSecret],
    new_secrets: Set[PotentialSecret],
) -> None:
    """
    Re-attaches human labels (e.g. `is_secret`) to results describing the same
    content in the same file, without relying on version-specific attributes
    (e.g. the detector type, which may be renamed between versions).

    Note that this intentionally applies a label to *all* results with matching
    content in the file, since they are indistinguishable without the detector type.

    This is only a fallback: results whose identity survived the regeneration keep
    their exact-match behaviour.
    """
    labelled_secrets: Dict[str, PotentialSecret] = {}
    for old_secret in old_secrets:
        if old_secret.is_secret is None and not old_secret.is_verified:
            continue

        labelled_secrets.setdefault(old_secret.secret_hash, old_secret)

    if not labelled_secrets:
        return

    old_identities = set(old_secrets)
    for new_secret in new_secrets:
        if new_secret in old_identities:
            continue

        labelled_secret = labelled_secrets.get(new_secret.secret_hash)
        if not labelled_secret:
            continue

        if not _is_distinctive_enough_for_label_match(new_secret, labelled_secret):
            continue

        # Only override if there's no newer value.
        if new_secret.is_secret is None:
            new_secret.is_secret = labelled_secret.is_secret

        # If the old value is false, it won't make a difference.
        if not new_secret.is_verified:
            new_secret.is_verified = labelled_secret.is_verified


def _is_distinctive_enough_for_label_match(
    new_secret: PotentialSecret,
    old_secret: PotentialSecret,
) -> bool:
    # Loaded baselines only store hashes, so the plaintext value may be unavailable.
    # Without it, we cannot tell whether the content is distinctive enough to safely
    # match on content alone, so we conservatively refuse.
    secret_value = new_secret.secret_value or old_secret.secret_value
    if not secret_value:
        return False

    return len(secret_value) >= MIN_CONTENT_LENGTH_FOR_LABEL_MATCH
