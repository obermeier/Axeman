import base64
import math

import datetime
from collections import OrderedDict

from OpenSSL import crypto

CTL_LISTS = 'https://www.gstatic.com/ct/log_list/v3/all_logs_list.json'
CTL_INFO = "{}/ct/v1/get-sth"
DOWNLOAD = "{}/ct/v1/get-entries?start={}&end={}"


from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, this, GreedyBytes, GreedyRange, Terminated

MerkleTreeHeader = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / GreedyBytes
)

Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)

PreCertEntry = Struct(
    "LeafCert" / Certificate,
    "CertificateChain" / CertificateChain,
    Terminated
)


async def retrieve_ctls(session=None, wanted_url=None, known_ctls=None, blacklisted_ctls=None):
    async with session.get(CTL_LISTS) as response:
        ctl_lists = await response.json()
        operators = ctl_lists['operators']

        logs = list()
        log = {}
        log['description'] = "Custom CTL"
        log['url'] = wanted_url
        logs.append(log)

        return logs


def _get_owner(log, owners):
    owner_id = log['operated_by'][0]
    owner = next(x for x in owners if x['id'] == owner_id)
    return owner['name']


async def get_max_block_size(log, session, size_reduce_factor):
    print(DOWNLOAD.format(log['url'], 0, size_reduce_factor))
    async with session.get(DOWNLOAD.format(log['url'], 0, (2000-size_reduce_factor))) as response:
        entries = await response.json()
        block_size = len(entries['entries'])
        print("FFFF BLK " + str(block_size) + "fff " + str(size_reduce_factor))
        if ((block_size - size_reduce_factor) > 0):
            return ( block_size - size_reduce_factor) # Reduce block size to minimize resource exhausted errors because of too large messages.
        else:
            return block_size


async def retrieve_log_info(log, session, size_reduce_factor):
    block_size = await get_max_block_size(log, session, size_reduce_factor)
    async with session.get(CTL_INFO.format(log['url'])) as response:
        info = await response.json()
        info['block_size'] = block_size
        info.update(log)
        return info


    async def populate_work(work_deque, log_info, start=0, end=0):
        tree_size = log_info["tree_size"]
        block_size = log_info["block_size"]

        if block_size <= 0:
            raise ValueError(f"Invalid block size: {block_size}")

        last_available_index = tree_size - 1

        if end != 0:
            last_index = min(end, last_available_index)
        else:
            last_index = last_available_index

        if start > last_index:
            return False

        block_start = (start // block_size) * block_size

        while block_start <= last_index:
            range_start = max(start, block_start)
            range_end = min(
                block_start + block_size - 1,
                last_index,
            )

            work_deque.append((
                range_start,
                range_end,
                start,
                end,
            ))

            block_start += block_size

        return bool(work_deque)


def add_all_domains(cert_data):
    all_domains = []

    # Apparently we have certificates with null CNs....what?
    if cert_data['leaf_cert']['subject']['CN']:
        all_domains.append(cert_data['leaf_cert']['subject']['CN'])

    SAN = cert_data['leaf_cert']['extensions'].get('subjectAltName')

    if SAN:
        for entry in SAN.split(', '):
            if entry.startswith('DNS:'):
                all_domains.append(entry.replace('DNS:', ''))

    cert_data['leaf_cert']['all_domains'] = list(OrderedDict.fromkeys(all_domains))

    return cert_data


def dump_cert(certificate):
    subject = certificate.get_subject()

    try:
        not_before = datetime.datetime.strptime(certificate.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp()
    except:
        not_before = 0

    try:
        not_after = datetime.datetime.strptime(certificate.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp()
    except:
        not_after = 0

    return {
        "subject": {
            "aggregated": repr(certificate.get_subject())[18:-2],
            "C": subject.C,
            "ST": subject.ST,
            "L": subject.L,
            "O": subject.O,
            "OU": subject.OU,
            "CN": subject.CN
        },
        "extensions": dump_extensions(certificate),
        "not_before": not_before,
        "not_after": not_after,
        "as_der": base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)).decode('utf-8'),
        #"fingerprint_sha1": str(certificate.digest("sha1"), encoding='utf-8'),
        "fingerprint_sha256": certificate.digest("sha256").decode("utf-8")
    }


def dump_extensions(certificate):
    extensions = {}
    for x in range(certificate.get_extension_count()):
        extension_name = ""
        try:
            extension_name = certificate.get_extension(x).get_short_name()

            if extension_name == b'UNDEF':
                continue

            extensions[extension_name.decode('latin-1')] = certificate.get_extension(x).__str__()
        except:
            try:
                extensions[extension_name.decode('latin-1')] = "NULL"
            except Exception as e:
                pass
    return extensions
