import os
import math
import base64
import hashlib
from asyncio import sleep
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

from kafka import KafkaProducer
from kafka.errors import KafkaError
from time import strftime, localtime
producer = None
import hashlib


from . import certlib

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

try:
    locale.setlocale(locale.LC_ALL, 'en_US')
except:
    pass

RETRY_WAIT = 8 
DOWNLOAD_CONCURRENCY = 4 
MAX_QUEUE_SIZE = 50 
PARTITION_SIZE=8000000
DEFAULT_TIMEOUT = ClientTimeout(connect=10)
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


def on_send_success(record_metadata):
    logging.debug(record_metadata.topic)
    logging.debug(record_metadata.partition)
    logging.debug(record_metadata.offset)

def on_send_error(excp):
    logging.error('I am an errback', exc_info=excp)

def write_to_kafka(metadata_list):
    global producer
    if producer is None:
        producer = KafkaProducer(bootstrap_servers=['80.241.209.21:9092'], value_serializer=lambda m: json.dumps(m).encode('ascii'))

    for metadata in metadata_list:
        future = producer.send('ctl-533', metadata).add_callback(on_send_success).add_errback(on_send_error)
        result = future.get(timeout=10)

async def download_worker(session, log_info, work_deque, download_queue):
    while True:
        try:
            start, end = work_deque.popleft()
        except IndexError:
            return

        logging.debug("[{}] Queueing up interval {}-{}...".format(log_info['url'], start, end))

        while True:
            try:
                async with session.get(certlib.DOWNLOAD.format(log_info['url'], start, end)) as response:
                    entry_list = await response.json()
                    logging.debug("[{}] Retrieved interval {}-{}...".format(log_info['url'], start, end))
                    break
            except Exception as e:
                # Normally "Attempt to decode JSON with unexpected mimetype"->"Too many connections" with "type text/plain;"
                # or a simple timeout. A bit of a hack, but I really don't wanna loose data here. A better solution would be
                # to have a separate waiting queue since this current implementation behaves much like a spin lock
                logging.info("Exception getting interval {}-{}, '{}', retrying in {} sec...".format(start, end, e, RETRY_WAIT))
                await sleep(RETRY_WAIT)

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


async def retrieve_certificates(loop, ctl_url, ctl_progress, only_known_ctls=False, output_directory='/tmp', concurrency_count=DOWNLOAD_CONCURRENCY, start_timerange=0, end_timerange=33266306427000, end_block=None):
    async with aiohttp.ClientSession(loop=loop, timeout=DEFAULT_TIMEOUT) as session:
        ctl_logs = await certlib.retrieve_ctls(session, ctl_url, ctl_progress.get_keys() if only_known_ctls else [], blacklisted_ctls=BAD_CTL_SERVERS)
        if not ctl_logs:
            logging.info("No ctl for URL found. [May not exist in list list]")
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
                result = await certlib.populate_work(work_deque, log_info, start=ctl_progress.get_offset(url), end=end_block)
                if not result:
                    logging.info("Log {} needs no update".format(url))
                    continue
            except Exception as e:
                logging.exception("Failed to populate work! {}".format(e))
                continue

            download_tasks = asyncio.gather(*[download_worker(session, log_info, work_deque, download_results_queue) for _ in range(concurrency_count)])
            processing_task = asyncio.ensure_future(processing_coro(download_results_queue, ctl_progress, output_directory))
            queue_monitor_task = asyncio.ensure_future(queue_monitor(log_info, work_deque, download_results_queue, ctl_progress))

            asyncio.ensure_future(download_tasks)

            await download_tasks

            await download_results_queue.put(None)  # Downloads are done, processing can stop

            await processing_task

            queue_monitor_task.cancel()

            logging.info("Completed {}, stored at {}/certificates/{}".format(log_info['description'], output_directory, log_info['url'].replace('https://', '')))

            ctl_progress.compress()
            ctl_progress.save()

            intervals = ctl_progress.get_intervals(log_info['url'])
            if intervals and len(intervals) > 1:
                logging.error("Number of intervals for url {} was {}, expected 0 or 1".format(log_info['url'], len(intervals)))


async def processing_coro(download_results_queue, ctl_progress, output_dir, partition_size=PARTITION_SIZE):
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

        for shard, entry in enumerate(entries_iter):
            friendly_log_name = entry['log_info']['url'].replace('https://', '').replace('/', '_')
            log_dir = '{}/certificates/{}'.format(output_dir, friendly_log_name)
            if not os.path.exists(log_dir):
                logging.debug("[{}] Making dir...".format(os.getpid()))
                os.makedirs(log_dir, exist_ok=True)
            offset_split=(int(entry['start']/partition_size))
            entry['csv_file'] = '{}/{}-shard-{}-part-{}.csv'.format(log_dir, friendly_log_name, shard, offset_split) 
            entry['csv_metadata_file'] = '{}/{}-shard-{}-part-{}-metadata.csv'.format(log_dir, friendly_log_name, shard, offset_split) 
            
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

    start = result_info['start']
    end = result_info['end']

    try:
        lines = []
        json_metadata = []
        lines_metadata = []

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
            crt_hash = cert_data['leaf_cert']['fingerprint_sha1']


            # header = "url, cert_index, chain_hash, cert_der, all_domains, not_before, not_after"
            #lines.append(
            #    ",".join([
            #        result_info['log_info']['url'],
            #        str(entry['cert_index']),
            #        chain_hash,
            #        cert_data['leaf_cert']['as_der'],
            #        '|'.join(cert_data['leaf_cert']['all_domains']),
            #        str(cert_data['leaf_cert']['not_before']),
            #        str(cert_data['leaf_cert']['not_after'])
            #    ]) + "\n"
            #)

            json_metadata.append({
                    'ctl_url': result_info['log_info']['url'],
                    'header_timestamp': mtl.Timestamp,
                    'cert_index': entry['cert_index'],
                    'cert_fingerprint_sha1': crt_hash
                })
            
            #lines_metadata.append(
            #    ",".join([
            #        result_info['log_info']['url'],
            #        str(mtl.Timestamp),
            #        str(cert_data['leaf_cert']['not_after']),
            #        str(cert_data['leaf_cert']['not_before']),
            #        str(entry['cert_index']),
            #        crt_hash
            #    ]) + "\n"
            #    )
            

        lines_expected = end - start + 1
        if len(lines) != lines_expected:
            logging.error("Too many or too few certificates found in interval {}-{}. Found {}, expected {}".format(start, end, len(lines), lines_expected))
        
        header_timestamp = (int(json_metadata[0]['header_timestamp']))
        #if header_timestamp >= start_timerange and header_timestamp <= end_timerange:
            #write_to_kafka(json_metadata)
        #else:
        #    print("Batch end reached: " + strftime('%Y-%m-%d %H:%M:%S', localtime(json_metadata[0]['header_timestamp']/1000)))


        # Write metadata
        csv_metatada_file = result_info['csv_metadata_file']
        with open(csv_metatada_file, 'a', encoding='utf8') as f:
            f.write("".join(lines_metadata))
        logging.debug("[{}] Interval {}-{} written to {}".format(os.getpid(), start, end, csv_metatada_file))

        # Stefan
        #csv_file = result_info['csv_file']
        #with open(csv_file, 'a', encoding='utf8') as f:
        #    f.write("".join(lines))
        #logging.debug("[{}] Interval {}-{} written to {}".format(os.getpid(), start, end, csv_file))

    except Exception as e:
        logging.exception("[{}] Failed to handle {}, interval {}-{}! {}".format(os.getpid(), result_info['log_info']['url'], start, end, e))

    return result_info['log_info']['url'], [start, end]


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

    parser.add_argument('-y', dest="ctl_offset_end", action="store", type=int, default=None, help="Number of blocks")
    
    parser.add_argument('-o', dest="output_dir", action="store", default=".", help="The output directory to store certificates in")

    parser.add_argument('-v', dest="verbose", action="store_true", help="Print out verbose/debug info")

    parser.add_argument('-c', dest='concurrency_count', action='store', default=DOWNLOAD_CONCURRENCY, type=int, help="The number of concurrent downloads to run at a time")

    parser.add_argument('-p', dest="progress_file", action="store", help="File hold the progress")

    parser.add_argument('-s', dest="starttime", type=int, action="store", help="Starttime from there on process the entries")

    parser.add_argument('-e', dest="endtime", type=int, action="store", help="Endtime from there on no entries will be processed.")

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
    
    # Hack Stefan
    global start_timerange
    start_timerange=0
    if args.starttime != None:
        start_timerange=int(args.starttime)
    
    global end_timerange
    end_timerange=96380168882000
    if args.endtime != None:
        end_timerange=int(args.endtime)

    if args.ctl_url:
        ctl_progress = CTLProgress(key=args.ctl_url.strip("'"), offset=int(args.ctl_offset), filename=args.progress_file)
        loop.run_until_complete(retrieve_certificates(loop, ctl_url=args.ctl_url.strip("'"), ctl_progress=ctl_progress, only_known_ctls=True, concurrency_count=args.concurrency_count, output_directory=args.output_dir, start_timerange=args.starttime, end_timerange=args.endtime,  end_block=args.ctl_offset_end))
    else:
        ctl_progress = CTLProgress(filename=args.progress_file)
        loop.run_until_complete(retrieve_certificates(loop,                                  ctl_progress=ctl_progress, concurrency_count=args.concurrency_count, output_directory=args.output_dir, start_timerange=args.starttime, end_timerange=args.endtime, end_block=args.ctl_offset_end))
    print(args.ctl_url)

if __name__ == "__main__":
    main()
