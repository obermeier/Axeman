import os
import math
import base64
import hashlib
import aiohttp
import aioprocessing
import logging
import locale
import json

import argparse
import asyncio
from collections import deque
import uvloop
from OpenSSL import crypto
from aiohttp import ClientTimeout

from axeman import certlib

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

try:
    locale.setlocale(locale.LC_ALL, 'en_US')
except:
    pass

MAX_RETRIES = 3
DOWNLOAD_CONCURRENCY = 50
MAX_QUEUE_SIZE = 1000
DEFAULT_TIMEOUT = ClientTimeout(connect=100)
BAD_CTL_SERVERS = [
    "ct.ws.symantec.com", "vega.ws.symantec.com", "deneb.ws.symantec.com", "sirius.ws.symantec.com",
    "log.certly.io", "ct.izenpe.com", "ct.izenpe.eus", "ct.wosign.com", "ctlog.wosign.com", "ctlog2.wosign.com",
    "ct.gdca.com.cn", "ctlog.api.venafi.com", "ctserver.cnnic.cn", "ct.startssl.com",
    "www.certificatetransparency.cn/ct", "flimsy.ct.nordu.net:8080", "ctlog.sheca.com",
    "log.gdca.com.cn", "log2.gdca.com.cn", "ct.sheca.com", "ct.akamai.com", "alpha.ctlogs.org",
    "clicky.ct.letsencrypt.org", "ct.filippo.io/behindthesofa", "ctlog.gdca.com.cn", "plausible.ct.nordu.net",
    "dodo.ct.comodo.com"
]


# This class is in no way thread safe!, And I really don't know if it need to...
class CTLProgress:
    def __init__(self, filename=None, key=None, offset=0):
        self.filename = filename
        self.progress = {}
        if key:
            self._set_offset(key, offset)
        if filename:
            self.load()

    def get_keys(self):
        return self.progress.keys()

    def get_intervals(self, key):
        intervals = self.progress.get(key)
        if intervals is None:
            intervals = []
            self.progress[key] = intervals
        return intervals

    def add_interval(self, key, interval):
        self.get_intervals(key).append(interval)

    def _clear_intervals(self, key):
        self.get_intervals(key).clear()

    def get_offset(self, key):
        intervals = self.get_intervals(key)
        return intervals[0][1] + 1 if intervals else 0

    def _set_offset(self, key, offset):
        self._clear_intervals(key)
        if offset > 0:
            self.add_interval(key, [0, offset - 1])

    def compress(self):
        for intervals in self.progress.values():
            sorted_intervals = sorted(intervals, key=lambda x: x[0])
            result = []
            for interval in sorted_intervals:
                if len(result) == 0 or result[-1][1] < interval[0] - 1:
                    result.append(interval)
                else:
                    result[-1][1] = max(result[-1][1], interval[1])
            intervals.clear()
            intervals.extend(result)

    def load(self):
        if not self.filename or not os.path.isfile(self.filename):
            return

        with open(self.filename, 'r', encoding='utf8') as f:
            progress = json.loads(f.read())
            for url, offset in progress.items():
                self._set_offset(url, offset)

    def save(self):
        if not self.filename:
            return

        with open(self.filename, 'w', encoding='utf8') as f:
            progress = {key: self.get_offset(key) for key in self.get_keys()}
            f.write(json.dumps(progress, indent=4))


async def download_worker(session, log_info, work_deque, download_queue, output_dir):
    while True:
        try:
            start, end = work_deque.popleft()
        except IndexError:
            return

        logging.debug("[{}] Queueing up interval {}-{}...".format(log_info['url'], start, end))

        for retry in range(MAX_RETRIES):  # Try MAX_RETRIES times
            try:
                async with session.get(certlib.DOWNLOAD.format(log_info['url'], start, end)) as response:
                    entry_list = await response.json()
                    logging.debug("[{}] Retrieved interval {}-{}...".format(log_info['url'], start, end))
                    break
            except Exception as e:
                if retry == MAX_RETRIES - 1:
                    logging.exception("Exception getting interval {}-{}! {}".format(start, end, e))
        else:  # Notorious for else, if we didn't encounter a break our request failed 3 times D:
            with open(output_dir + '/fails.csv', 'a') as f:
                f.write(",".join([log_info['url'], str(start), str(end)]) + "\n")
            continue

        for index, entry in zip(range(start, end + 1), entry_list['entries']):
            entry['cert_index'] = index

        await download_queue.put({
            'entries': entry_list['entries'],
            'log_info': log_info,
            'start': start,
            'end': end
        })


async def queue_monitor(log_info, work_deque, download_results_queue, ctl_progress):
    total_size = log_info['tree_size'] - 1
    total_blocks = math.ceil(total_size / log_info['block_size'])

    while True:
        logging.info("Queue Status: Processing Queue Size:{0} Downloaded blocks:{1}/{2} ({3:.4f}%)".format(
            download_results_queue.qsize(),
            total_blocks - len(work_deque),
            total_blocks,
            ((total_blocks - len(work_deque)) / total_blocks) * 100,
        ))

        ctl_progress.compress()
        ctl_progress.save()

        await asyncio.sleep(2)


async def retrieve_certificates(loop, ctl_progress, only_known_ctls=False, output_directory='/tmp', concurrency_count=DOWNLOAD_CONCURRENCY):
    async with aiohttp.ClientSession(loop=loop, timeout=DEFAULT_TIMEOUT) as session:
        ctl_logs = await certlib.retrieve_ctls(session, ctl_progress.get_keys() if only_known_ctls else [], blacklisted_ctls=BAD_CTL_SERVERS)

        for log in ctl_logs:
            url = log['url']
            work_deque = deque()
            download_results_queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)

            logging.info("Downloading certificates for {}".format(log['description']))
            try:
                log_info = await certlib.retrieve_log_info(log, session)
            except (aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError, aiohttp.ClientOSError, aiohttp.ClientResponseError) as e:
                logging.exception("Failed to connect to CTL! -> {} - skipping.".format(e))
                continue

            try:
                result = await certlib.populate_work(work_deque, log_info, start=ctl_progress.get_offset(url))
                if not result:
                    logging.info("Log {} needs no update".format(url))
                    continue
            except Exception as e:
                logging.exception("Failed to populate work! {}".format(e))
                continue

            download_tasks = asyncio.gather(*[download_worker(session, log_info, work_deque, download_results_queue, output_directory) for _ in range(concurrency_count)])
            processing_task = asyncio.ensure_future(processing_coro(download_results_queue, ctl_progress, output_directory))
            queue_monitor_task = asyncio.ensure_future(queue_monitor(log_info, work_deque, download_results_queue, ctl_progress))

            asyncio.ensure_future(download_tasks)

            await download_tasks

            await download_results_queue.put(None)  # Downloads are done, processing can stop

            await processing_task

            queue_monitor_task.cancel()

            logging.info("Completed {}, stored at {}/certificates/{}".format(log_info['description'], output_directory, log_info['url'].replace('/', '_')))

            ctl_progress.compress()
            ctl_progress.save()

            intervals = ctl_progress.get_intervals(log_info['url'])
            if intervals and len(intervals) > 1:
                logging.error("Number of intervals for url {} was {}, expected 0 or 1".format(log_info['url'], len(intervals)))


async def processing_coro(download_results_queue, ctl_progress, output_dir):
    logging.debug("Starting processing coro and process pool")
    process_pool = aioprocessing.AioPool(initargs=(output_dir,))

    done = False

    while True:
        entries_iter = []
        logging.debug("Getting things to process...")
        for _ in range(int(process_pool.pool_workers)):
            entries = await download_results_queue.get()
            if entries is not None:
                entries_iter.append(entries)
            else:
                done = True
                break

        logging.debug("Got a chunk of {}. Mapping into process pool".format(process_pool.pool_workers))

        for entry in entries_iter:
            csv_storage = '{}/certificates/{}'.format(output_dir, entry['log_info']['url'].replace('/', '_'))
            if not os.path.exists(csv_storage):
                logging.debug("[{}] Making dir...".format(os.getpid()))
                os.makedirs(csv_storage)
            entry['log_dir'] = csv_storage

        if len(entries_iter) > 0:
            result = await process_pool.coro_map(process_worker, entries_iter)
            [ctl_progress.add_interval(r[0], r[1]) for r in result if r]

        logging.debug("Done mapping! Got results")

        if done:
            break

    process_pool.close()

    await process_pool.coro_join()


def process_worker(result_info):
    logging.debug("Worker {} starting...".format(os.getpid()))
    if not result_info:
        return None

    try:
        csv_storage = result_info['log_dir']
        csv_file = "{}/{}-{}.csv".format(csv_storage, result_info['start'], result_info['end'])

        lines = []

        logging.debug("[{}] Parsing...".format(os.getpid()))
        for entry in result_info['entries']:
            mtl = certlib.MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))

            cert_data = {}

            if mtl.LogEntryType == "X509LogEntryType":
                cert_data['type'] = "X509LogEntry"
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, certlib.Certificate.parse(mtl.Entry).CertData)]
                extra_data = certlib.CertificateChain.parse(base64.b64decode(entry['extra_data']))
                for cert in extra_data.Chain:
                    chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
            else:
                cert_data['type'] = "PreCertEntry"
                extra_data = certlib.PreCertEntry.parse(base64.b64decode(entry['extra_data']))
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]

                for cert in extra_data.Chain:
                    chain.append(
                        crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
                    )

            cert_data.update({
                'leaf_cert': certlib.dump_cert(chain[0]),
                'chain': [certlib.dump_cert(x) for x in chain[1:]]
            })

            certlib.add_all_domains(cert_data)

            cert_data['source'] = {
                'url': result_info['log_info']['url'],
            }

            chain_hash = hashlib.sha256("".join([x['as_der'] for x in cert_data['chain']]).encode('ascii')).hexdigest()

            # header = "url, cert_index, chain_hash, cert_der, all_domains, not_before, not_after"
            lines.append(
                ",".join([
                    result_info['log_info']['url'],
                    str(entry['cert_index']),
                    chain_hash,
                    cert_data['leaf_cert']['as_der'],
                    ' '.join(cert_data['leaf_cert']['all_domains']),
                    str(cert_data['leaf_cert']['not_before']),
                    str(cert_data['leaf_cert']['not_after'])
                ]) + "\n"
            )

        lines_expected = result_info['end'] - result_info['start'] + 1
        if len(lines) != lines_expected:
            logging.error("Too many or too few certificates found in {}. Found {}, expected {}".format(csv_file, len(lines), lines_expected))
        csv_file_tmp = csv_file + ".tmp"
        with open(csv_file_tmp, 'w', encoding='utf8') as f:
            f.write("".join(lines))
        os.rename(csv_file_tmp, csv_file)  # Ensures the .csv is fully written before other systems can grab it
        logging.debug("[{}] CSV {} written!".format(os.getpid(), csv_file))

    except Exception as e:
        logging.exception("[{}] Failed to handle {}, interval {}-{}! {}".format(os.getpid(), result_info['log_info']['url'], result_info['start'], result_info['end'], e))

    return result_info['log_info']['url'], [result_info['start'], result_info['end']]


async def get_certs_and_print():
    async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT) as session:
        total_count = 0
        ctls = await certlib.retrieve_ctls(session, blacklisted_ctls=BAD_CTL_SERVERS)
        print("Found {} CTLs...".format(len(ctls)))
        for i, log in enumerate(ctls):
            print("{} - {}".format(i, log['description']))
            print("    \\- URL:            {}".format(log['url']))

            if log.get('disqualified_at'):
                print("    \\- Status:         DISQUALIFIED\n")
                continue

            try:
                log_info = await certlib.retrieve_log_info(log, session)
                print("    \\- Status:         OK")
                print("    \\- Owner:          {}".format(log_info['operated_by']))
                print("    \\- Cert Count:     {}".format(locale.format("%d", log_info['tree_size'], grouping=True)))
                print("    \\- Max Block Size: {}\n".format(log_info['block_size']))
                total_count += log_info['tree_size']
            except:
                print("    \\- Status:         FAILED\n")

        print("Total certificate count: {}".format(locale.format("%d", total_count, grouping=True)))


def main():
    loop = asyncio.get_event_loop()

    parser = argparse.ArgumentParser(description='Pull down certificate transparency list information')

    parser.add_argument('-f', dest='log_file', action='store', default='./axeman.log', help='Location for the axeman log file')

    parser.add_argument('-l', dest="list_mode", action="store_true", help="List all available certificate lists")

    parser.add_argument('-u', dest="ctl_url", action="store", help="Retrieve this CTL only")

    parser.add_argument('-z', dest="ctl_offset", action="store", default=0, help="The CTL offset to start at")

    parser.add_argument('-o', dest="output_dir", action="store", default=".", help="The output directory to store certificates in")

    parser.add_argument('-v', dest="verbose", action="store_true", help="Print out verbose/debug info")

    parser.add_argument('-c', dest='concurrency_count', action='store', default=50, type=int, help="The number of concurrent downloads to run at a time")

    parser.add_argument('-p', dest="progress_file", action="store", help="File hold the progress")

    args = parser.parse_args()

    if args.list_mode:
        loop.run_until_complete(get_certs_and_print())
        return

    handlers = [logging.FileHandler(args.log_file), logging.StreamHandler()]

    if args.verbose:
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.DEBUG, handlers=handlers)
    else:
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO, handlers=handlers)

    logging.info("Starting...")

    if args.ctl_url:
        ctl_progress = CTLProgress(key=args.ctl_url.strip("'"), offset=int(args.ctl_offset), filename=args.progress_file)
        loop.run_until_complete(retrieve_certificates(loop, ctl_progress=ctl_progress, only_known_ctls=True, concurrency_count=args.concurrency_count, output_directory=args.output_dir))
    else:
        ctl_progress = CTLProgress(filename=args.progress_file)
        loop.run_until_complete(retrieve_certificates(loop, ctl_progress=ctl_progress, concurrency_count=args.concurrency_count, output_directory=args.output_dir))


if __name__ == "__main__":
    main()
