# vim: sw=4:ts=4:et

import gzip
import hashlib
import io
import json
import logging
import os.path
import re
import shutil
import smtplib
import sys
import tempfile
import threading
import time
import traceback
import warnings
import zipfile

from subprocess import Popen, PIPE

import requests

__all__ = [
    'VXSTREAM_STATUS_UNKNOWN',
    'VXSTREAM_STATUS_IN_QUEUE',
    'VXSTREAM_STATUS_IN_PROGRESS',
    'VXSTREAM_STATUS_ERROR',
    'VXSTREAM_STATUS_SUCCESS',
    'VxStreamServer',
    'VxStreamSubmission',
    'VXSTREAM_DOWNLOAD_JSON',
    'VXSTREAM_DOWNLOAD_XML',
    'VXSTREAM_DOWNLOAD_HTML',
    'VXSTREAM_DOWNLOAD_SAMPLE',
    'VXSTREAM_DOWNLOAD_PCAP',
    'VXSTREAM_DOWNLOAD_MEMORY',
]

# default installation directory
VXSTREAM_BASE_DIR = '/opt/vxstream'

# sample submission status
VXSTREAM_STATUS_UNKNOWN = 'UNKNOWN'
VXSTREAM_STATUS_IN_QUEUE = 'IN_QUEUE'
VXSTREAM_STATUS_IN_PROGRESS = 'IN_PROGRESS'
VXSTREAM_STATUS_ERROR = 'ERROR'
VXSTREAM_STATUS_SUCCESS = 'SUCCESS'

# result types
VXSTREAM_DOWNLOAD_JSON = 'json'
VXSTREAM_DOWNLOAD_XML = 'xml'
VXSTREAM_DOWNLOAD_HTML = 'html'
VXSTREAM_DOWNLOAD_SAMPLE = 'bin'
VXSTREAM_DOWNLOAD_PCAP = 'pcap'
VXSTREAM_DOWNLOAD_MEMORY = 'memory'

# for extrating file paths from 7z command
REGEX_7Z = re.compile('^Extracting\s+(.+)$')

# required user-agent settings
VXSTREAM_HEADERS = { 'User-agent': 'VxStream Sandbox' }

# some symbolic names for indexes

class VxStreamDownloadResults(object):
    def __init__(self, submission):
        self.submission = submission
        self.json_path = None
        self.pcap_path = None
        self.xml_path = None
        self.html_path = None
        self.dropped_files = []
        self.memory_dump_files = []
        self.combined_memory_dump_path = None

    #def all_files(self):
        #"""Returns a list of all files collected from the vxstream analysis."""

        #result = []
        #for file_path in [
            #self.json_path,
            #self.pcap_path,
            #self.xml_path,
            #self.html_path ]:
            #if file_path is not None:
                #result.append(file_path)

        #result.extend(self.dropped_files)
        #result.extend(self.memory_dump_files)
        #if self.combined_memory_dump_path is not None:
            #result.append(self.combined_memory_dump_path)

        #return result

class VxStreamSubmission(object):
    """Represents a sample that was submitted to VxStream."""
    def __init__(self, file_name, sha256, environment_id):
        self.file_name = file_name
        self.sha256 = sha256
        self.environment_id = environment_id
        self.status = None

    def __str__(self):
        return self.file_name

class VxStreamSubmissionManager(object):
    """Utility class that manages multiple submissions with notification callbacks."""
    def __init__(self, server, submissions, delay=1):
        assert isinstance(server, VxStreamServer)
        assert delay >= 1
        assert len(submissions) > 0

        self.server = server
        self.submissions = {} # key = sha256, value = VxStreamSubmission
        self.callbacks = [] # a list of functions to call when the status of a sample has changed

        # how often to check sample status
        self.delay = delay

        # controls the thread
        self.shutdown = False

        for submission in submissions:
            self.submissions[submission.sha256] = submission

    def add_callback(self, callback):
        """Adds a function(server, status) to be called when the status of a sample has changed."""
        self.callbacks.append(callback)

    def start(self):
        self.thread = threading.Thread(target=self.run, name=str(type(self)))
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.shutdown = True
        if self.thread is not None and self.thread.is_alive():
            logging.debug("stopping {}".format(self.thread))
            self.thread.join(self.delay + 2) # give it two seconds to stop
            if self.thread.is_alive():
                logging.error("{} failed to stop".format(self.thread))

    def run(self):
        while not self.shutdown:
            try:
                self.execute()
            except Exception as e:
                logging.error(str(e))
                traceback.print_exc()

            time.sleep(1)

    def execute(self):
        completed = [] # list of submissions that have completed

        for submission in self.submissions.values():
            result = server.get_status(submission.sha256, submission.environment_id)
            if result == VXSTREAM_STATUS_ERROR:
                logging.info("detected error in file {}".format(submission))
                completed.append(submission)

            elif result == VXSTREAM_STATUS_SUCCESS:
                logging.info("detected completed file {}".format(submission))
                completed.append(submission)

            if submission.status != result:
                logging.info("sample {} changed state from {} to {}".format(submission, submission.status, result))
                submission.status = result

                # call all notifications for this sample
                for callback in self.callbacks:
                    try:
                        callback(self.server, submission)
                    except Exception as e:
                        logging.error("error executing {}: {}".format(str(callback), str(e)))

        for submission in completed:
            del self.submissions[submission.sha256]

        if len(self.submissions) == 0:
            logging.info("finished all submissions")
            self.shutdown = True

    def wait(self):
        """Waits for all submitted jobs to complete."""
        logging.info("waiting for {} jobs to complete".format(len(self.submissions)))
        while not self.shutdown:
            time.sleep(1)

class VxStreamServer(object):
    def __init__(self, url, api_key, secret, proxies={}):
        # set this to True to shut down any outstanding requests
        self.shutdown = False

        # base vxstream url
        self.url = url
        while self.url.endswith('/'):
            self.url = self.url[:-1]

        # various URLs we use
        #self.submit_url = '{}/submit'.format(self.url)
        #self.result_url = '{}/result'.format(self.url)
        #self.state_url = '{}/state'.format(self.url)

        self.api_key = api_key
        self.secret = secret

        # how long do we wait in between status requests? (in seconds)
        self.query_frequency = 1

        # optional proxy settings
        self.proxies = proxies

    def get_status(self, sha256, environment_id):
        status_url = '{}/api/state/{}'.format(
            self.url, 
            self.get_sample_url(sha256, environment_id))

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = requests.get(status_url, verify=False, headers=VXSTREAM_HEADERS, proxies=self.proxies) # XXX

        if result.status_code != 200:
            logging.error("got result {} from vxstream: {}".format(result.status_code, result.reason))
            return None

        # the result looks like this
        # '{\n    "response_code": 0,\n    "response": {\n        "state": "SUCCESS"\n    }\n}'

        json_result = json.loads(result.text)
        logging.debug("got response_code {} state {} for sha256 {} environment_id {}".format(
            json_result['response_code'], 
            json_result['response']['state'],
            sha256,
            environment_id))
        
        return json_result['response']['state']

    def get_sample_url(self, sha256, environment_id):
        return '{}/?apikey={}&secret={}&environmentId={}'.format(
            sha256, self.api_key, self.secret, environment_id)

    def result_url(self, result_type):
        return '{}/result/{}&type={}'.format(self.state_url, self.get_url(), result_type)

    def reanalyze(self, file_path, environment_id):
        data = {
            'apikey': self.api_key, 
            'secret': self.secret, 
            'environmentId': environment_id }

        hasher = hashlib.sha256()
        with open(file_path, 'rb') as fp:
            while True:
                data = fp.read(io.DEFAULT_BUFFER_SIZE)
                if data == b'':
                    break
                hasher.update(data)

        sha256 = hasher.hexdigest()

        url = '{}/api/reanalyze/{}'.format(self.url, sha256)

        result = requests.post(url, data=data, verify=False, headers=VXSTREAM_HEADERS, proxies=self.proxies) # XXX
        logging.debug("got response_code {} for {}".format(result.status_code, url))
        if result.status_code != 200:
            logging.error("error code {} ({}) returned for {}".format(result.status_code, result.reason, sha256))
            return None

        status = self.get_status(sha256, environment_id)
        logging.debug("got status {} for {}".format(status, sha256))
        result = VxStreamSubmission(file_path, sha256, environment_id)
        result.status = status
        return result

    def submit(self, file_path, environment_id):
        # make sure we haven't already submitted this, eh?
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as fp:
            while True:
                data = fp.read(io.DEFAULT_BUFFER_SIZE)
                if data == b'':
                    break
                hasher.update(data)

        sha256 = hasher.hexdigest()
        status = self.get_status(sha256, environment_id)
        if status != VXSTREAM_STATUS_UNKNOWN:
            logging.info("{} already uploaded".format(file_path))
            result = VxStreamSubmission(file_path, sha256, environment_id)
            result.status = status
            return result

        with open(file_path, 'rb') as fp_binary:
            # submit the file to vxstream
            files = { 'file': fp_binary }
            data = {
                'apikey': self.api_key, 
                'secret': self.secret, 
                'environmentId': environment_id }
            submit_url = '{}/api/submit'.format(self.url)

            logging.info("submitting {} to {} environment {}".format(file_path, submit_url, environment_id))

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = requests.post(submit_url, data=data, files=files, verify=False, headers=VXSTREAM_HEADERS, proxies=self.proxies) # XXX

            if result.status_code != 200:
                logging.error("error code {} ({}) returned for {}".format(result.status_code, result.reason, file_path))
                return None

        return VxStreamSubmission(file_path, sha256, environment_id)

    def wait(self, sha256, environment_id):
        current_status = None
        while not self.shutdown:
            status = self.get_status(sha256, environment_id)
            if current_status != status:
                logging.info("{} status changed to {}".format(sha256, status))
                current_status = status

            if status == VXSTREAM_STATUS_ERROR:
                logging.info("detected error state for {}".format(sha256))
                return VXSTREAM_STATUS_ERROR

            if status == VXSTREAM_STATUS_SUCCESS:
                logging.info("{} completed".format(sha256))
                return VXSTREAM_STATUS_SUCCESS

            time.sleep(self.query_frequency)

    def download(self, sha256, environment_id, _type, path):
        download_url = '{}/api/result/{}&type={}'.format(
            self.url, 
            self.get_sample_url(sha256, environment_id),
            _type)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            logging.info("downloading {} for {} env {}".format(_type, sha256, environment_id))
            result = requests.get(download_url, verify=False, headers=VXSTREAM_HEADERS, proxies=self.proxies) # XXX

        if result.status_code != 200:
            logging.error("got result {} from vxstream: {}".format(result.status_code, result.reason))
            return None

        with open(path, 'wb') as fp:
            for block in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(block)

        return path

    def download_dropped_files(self, sha256, environment_id, target_dir):
        """Downloads the dropped files for this sample into target_dir.  Returns the list of files extracted."""

        download_url = '{}/api/sample-dropped-files/{}?environmentId={}&apikey={}&secret={}'.format(
            self.url,
            sha256,
            environment_id,
            self.api_key,
            self.secret)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            logging.info("downloading dropped files from {}".format(download_url))
            result = requests.get(download_url, verify=False, headers=VXSTREAM_HEADERS, proxies=self.proxies) # XXX

        if result.status_code != 200:
            logging.error("got result {} from vxstream for {}: {}".format(result.status_code, download_url, result.reason))
            return None

        # put what we download into a temporary directory
        temp_dir = tempfile.mkdtemp()
        try:
            # all dropped files come in a zip file
            compressed_path = os.path.join(temp_dir, 'download.zip')

            # write zip file to disk
            with open(compressed_path, 'wb') as fp:
                for block in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                    fp.write(block)

            # unzip without paths
            p = Popen(['7z', 'e', '-y', '-o{}'.format(target_dir), compressed_path], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate()

            try:
                os.remove(compressed_path)
            except Exception as e:
                logging.error("unable to delete {}: {}".format(compressed_path, e))

            # list gz files in drop_path
            file_list = [os.path.join(target_dir, f) for f in os.listdir(target_dir) if f.endswith('.gz')]

            result = []
            for compressed_path in file_list:
                # there are some other files in here sometimes that we'll ignore
                # we just want the dropped file
                if '.DROPPED.' not in compressed_path:
                    continue

                DROPPED_FILE_REGEX = re.compile(r'^(.+?)\.[0-9]+\.DROPPED\.gz')

                # the file paths look like this
                # dropped/78QC7UOHAWCI47906LWH.temp.4212842214.DROPPED.gZ
                m = DROPPED_FILE_REGEX.match(os.path.basename(compressed_path))
                if not m:
                    logging.error("could not extract file name from {}".format(compressed_path))
                    continue

                target_path = os.path.join(target_dir, m.group(1))
                result.append(target_path)

                with gzip.open(compressed_path) as fp:
                    logging.debug("decompressing {}".format(compressed_path))
                    with open(target_path, 'wb') as dest_fp:
                        while True:
                            data = fp.read(io.DEFAULT_BUFFER_SIZE)
                            if data == b'':
                                break

                            dest_fp.write(data)

                os.remove(compressed_path)

            return result

        finally:

            try:
                if temp_dir:
                    shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error("unable to delete temporary directory {}: {}".format(temp_dir, e))

    def download_memory_dump(self, sha256, environment_id, dest_dir):
        """Downloads the given memory dump into the given directory.  Returns a tuple of a list of files extracted from what was downloaded, and the path to the combined memory dump."""

        dest_path = os.path.join(dest_dir, 'memory.zip')
        if self.download(sha256, environment_id, VXSTREAM_DOWNLOAD_MEMORY, dest_path) is None:
            return None

        with open(dest_path, 'rb') as fp:
            blob = fp.read(1024)
            if b'No dump files available' in blob:
                logging.debug("memory dump not available for {} env {}".format(sha256, environment_id))
                return None

        logging.debug("extracting memory dump {} into {}".format(dest_path, dest_dir))
        p = Popen(['7z', 'x', '-y', '-o{}'.format(dest_dir), dest_path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()

        file_list = []
        for file_path in [os.path.join(dest_dir, f) for f in os.listdir(dest_dir) if f != "memory.zip"]:
            file_list.append(file_path)

        # concatenate all these files into one file
        dest_path = os.path.join(dest_dir, 'memory.combined.mdmp')
        for file_path in file_list:
            logging.debug("concatenating {}".format(file_path))
            with open(file_path, 'rb') as input_fp:
                with open(dest_path, 'ab') as output_fp:
                    while True:
                        data = input_fp.read(io.DEFAULT_BUFFER_SIZE)
                        if data == b'':
                            break

                        output_fp.write(data)

        return file_list, dest_path

def main():

    import argparse
    
    parser = argparse.ArgumentParser(description="Submit one or more files to vxstream for processing.")
    parser.add_argument('files', nargs="*", help="Zero or more files to submit.  Also see --from-stdin")
    parser.add_argument('--from-stdin', required=False, default=False, action='store_true', dest='from_stdin',
        help="Read the files to scan from standard input.")
    parser.add_argument('--sha256', required=False, default=None, dest='sha256',
        help="Download the results of the given sha256 hash.")
    parser.add_argument('--environment_id', required=False, default='3', dest='environment_id',
        help="Select the environment ID to use.")
    parser.add_argument('-u', '--url', required=False, default='https://vxstream.local', dest='url',
        help="The URI to submit the files to.")
    parser.add_argument('-d', '--dir', required=False, default='vxstream.out', dest='output_dir',
        help="The output directory to place the downloaded results into.")
    parser.add_argument('-l', '--log-level', required=False, default='WARNING', dest='log_level',
        help="The logging level to use for log events.")
    #parser.add_argument('--decompress', required=False, default=False, action='store_true', dest='decompress',
        #help="Automatically decompress and extract dropped files and memory dumps.")
    #parser.add_argument('--download-html', required=False, default=False, action='store_true', dest='download_html',
        #help="Also download the HTML report.")
    #parser.add_argument('--download-xml', required=False, default=False, action='store_true', dest='download_xml',
        #help="Also download the XML report.")
    #parser.add_argument('--download-dropped-files', required=False, default=False, action='store_true', dest='download_dropped_files',
        #help="Also download the dropped files.")
    parser.add_argument('-e', '--email', required=False, action='append', default=[], dest='email_addresses',
        help="Send an email when completed.  Can specify more than one of these options.")
    parser.add_argument('--smtp-server', required=False, default='ashsmtp.asco.ashland.com', dest='smtp_server',
        help="Specify an alternate SMTP server to use.")
    parser.add_argument('--api-key', required=False, default='', dest='api_key')
    parser.add_argument('--secret', required=False, default='', dest='secret')
    parser.add_argument('--delay', required=False, default=1, type=int, dest='delay',
        help="The number of seconds to delay in between each attempt to query status of submitted files.")
    parser.add_argument('--split-memory-dump', required=False, default=False, action='store_true', dest='split_memory',
        help="Download the memory dump as separate files instead of an individual file.")

    args = parser.parse_args()

    logging.basicConfig(level=args.log_level, format='[%(asctime)s] [%(levelname)s] - %(message)s')
    logging.getLogger("requests").setLevel(logging.WARNING)

    if not os.path.isdir(args.output_dir):
        try:
            os.makedirs(args.output_dir)
        except Exception as e:
            logging.error("unable to create output directory {}: {}".format(args.output_dir, str(e)))
            sys.exit(1)

    server = VxStreamServer(args.url, args.api_key, args.secret)
    submissions = [] # list of VxStreamSubmission objects we will be tracking

    if args.sha256 is not None:
        submissions.append(VxStreamSubmission('(unknown)', args.sha256, args.environment_id))
    else:
        # are we reading list of files from command line or stdin?
        file_list = args.files
        if args.from_stdin:
            file_list = sys.stdin
            
        for f in file_list:
            # files from stdin will have trailing return
            if args.from_stdin:
                f = f.strip()

            submission = server.submit(f, args.environment_id)
            if submission is None:
                continue

            submissions.append(submission)

    if len(submissions) == 0:
        logging.error("no files were submitted")
        sys.exit(1)

    def state_change_handler(server, submission):
        if submission.status == VXSTREAM_STATUS_SUCCESS:
            result = server.download_results(submission, args.output_dir)
            for file_path in [
                result.json_path,
                result.pcap_path,
                result.xml_path,
                result.html_path ]:
                if file_path is not None:
                    print(file_path)

            for file_path in result.dropped_files:
                print(file_path)
            
            if args.split_memory:
                for file_path in result.memory_dump_files:
                    print(file_path)
            else:
                if result.combined_memory_dump_path is not None:
                    print(result.combined_memory_dump_path)

            symlink_path = os.path.join(args.output_dir, os.path.basename(submission.file_name))
            if not os.path.lexists(symlink_path):
                try:
                    os.symlink(os.path.basename(os.path.dirname(result.json_path)), symlink_path)
                except Exception as e:
                    logging.error("unable to create symlink {}: {}".format(symlink_path, str(e)))

    manager = VxStreamSubmissionManager(server, submissions, delay=args.delay)
    manager.add_callback(state_change_handler)
    manager.start()
    manager.wait()

if __name__ == '__main__':
    main()
