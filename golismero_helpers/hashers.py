import mmh3

from typing import List


def hash_ip(data: dict):
    return mmh3.hash128(data['ip'])


def hash_domain(data: dict):
    return mmh3.hash128(data['domain'])


def hash_vulnerability(data: dict):
    string_hash = []
    for x in ('cve', 'id', 'cwe', 'title'):
        if x in data:
            string_hash.append(data[x])

    return mmh3.hash128("#".join(string_hash))


DATA_TYPES_HASHERS = {
    'ip': hash_ip,
    'domain': hash_domain,
    'vulnerability': hash_vulnerability,
}


def calculate_hash(data: List[dict] or dict):
    """
    This function make the hash of each data type and create a hash for a
    data composition
    """
    if type(data) is not list:
        data = [data]

    carry = []

    for d in data:
        try:
            h = DATA_TYPES_HASHERS[d['_type']](d)
        except KeyError:
            # TODO: IMPROVE THAT!!!
            # If we can't calculate the hash of a type, use all of non-metadata
            # properties for the hash
            h = mmh3.hash128("#".join(
                y for x, y in d.items() if not x.startswith("_"))
            )

        carry.append(h)

    return mmh3.hash128("#".join(str(x) for x in carry))


__all__ = ("calculate_hash",)
