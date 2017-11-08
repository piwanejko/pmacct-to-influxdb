from influxdb import InfluxDBClient, exceptions
from datetime import datetime, timedelta
from threading import Timer, Thread, main_thread
from sys import exit
from json import loads
from inotify.adapters import Inotify
from _thread import interrupt_main
import socket
import logging


# Logging options
logging.basicConfig(filename='pmacct_to_influxdb.log',
                    format='%(asctime)s (%(levelname)s) %(message)s')
logger = logging.getLogger('pmacct_to_influxdb')
logger.setLevel(logging.ERROR)


# InfluxDB connection data
_INFLUX_HOST = 'x.x.x.x'
_INFLUX_PORT = 8086
_INFLUX_USERNAME = '_username_'
_INFLUX_PASSWORD = '_password_'
_INFLUX_DATABASE = 'sflow_global_traffic'


# InfluxDB measurements for pmacct data
_TRAFFIC_MEASUREMENT = 'traffic'
_TOP_TALKERS_MEASUREMENT = 'top_talkers'
_TOP_TALKERS_COUNT = 30


# Pmacct data file
_PMACCT_DATA = 'global_asn_traffic.txt'


# ASN to names data file
_ASN_TO_NAMES = 'asn_to_names.txt'


def check_whois(asn):
    """ For given AS number function returns data related to AS from CYMRU whois server, for example:
    "ALCORT", "ES"
    If there's no data received "_unknown_" and "00" are passed as as-name and as-country.
    In case of connection problem function returns None, None as calling function expects two parameters.
    """
    asn_request = 'AS{}\n'.format(asn)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('v4.whois.cymru.com', 43))
    except socket.timeout:
        logger.error('Could not connect to whois server, ignoring entry for AS{}'.format(asn))
        return None, None
    except socket.gaierror:
        logger.error('Could not resolve whois server name, ignoring entry for AS{}'.format(asn))
        return None, None
    # From python 3.3 all socket errors raise OSError or one of its subclasses
    # https://docs.python.org/3/library/socket.html
    except OSError:
        logger.error('Whois server connection problem, ignoring entry for AS{}'.format(asn))
        return None, None
    else:
        try:
            sock.send(asn_request.encode())
            data = sock.recv(4096)
            logger.debug("Received message from whois server for asn {} : {}".format(asn, data))
            if data:
                decoded_data = data.decode().split('\n')[1]
                asn_name = decoded_data[:-4]
                asn_country = decoded_data[-2:]
                # Sometimes as-name parameter is not defined ans whois returns empty string for it
                if asn_name == '':
                    asn_name = '_unspecified_'
                # Whois as-name: object can be really long, cutting to just want first word for clarity
                else:
                    asn_name = asn_name.split()[0]
            else:
                return '_unknown_', '00'
            return asn_name, asn_country
        except ConnectionResetError:
            logger.error("Whois connection reset, probably peer closed connection")
            return None, None
    finally:
        sock.close()


def asn_to_name(asn):
    """ Function is searching _ASN_TO_NAMES file for ASN data. If there's no match, check_whois(asn) is called.
    If returned values are None, None is returned as well. Otherwise list [asn_country, asn_name] is passed as output.
    """
    asn_file = open(_ASN_TO_NAMES, 'a+')
    # File is opened in append mode, we need to move back to beginning
    asn_file.seek(0)
    for line in asn_file.readlines():
        if int(line.split()[0]) == asn:
            return [line.split()[1], line[20:-1]]

    # If ASN data is not found in cache file
    asn_name, asn_country = check_whois(asn)
    if not asn_name and not asn_country:
        return None
    # Writing missing ASN data to file
    asn_file.write('{:<10}{:<10}{}\n'.format(asn, asn_country, asn_name))
    logger.debug('Added to ASN file: {} ({}) {}'.format(asn, asn_country, asn_name))
    asn_file.close()
    return [asn_country, asn_name]


def write_to_db():
    """ When called function reads pmacct JSONized data stored in _PMACCT_DATA file:
        {"packets": 36542464, "as_dst": 123, "bytes": 52984530944}
        {"packets": 389120, "as_dst": 124, "bytes": 572760064}
        {"packets": 4237312, "as_dst": 125, "bytes": 6393528320}
        ...
        and for each line it writes points to influxdb. Each point has 'ASN' tag with ASN description for example,
        for ASN 2856 "AS2856 BT-UK-AS (GB)"
        If any client or server side error occurs proper log entry is created and script exits all threads.
    """
    db_client = InfluxDBClient(_INFLUX_HOST, _INFLUX_PORT, _INFLUX_USERNAME, _INFLUX_PASSWORD, _INFLUX_DATABASE)
    data_file = open(_PMACCT_DATA)
    write_counter = 0
    for line in data_file.readlines():
        # Parsing JSON to dictionary
        line_dict = loads(line)
        # Expecting two element list [asn_country, asn_name]
        asn_list = asn_to_name(line_dict['as_dst'])
        if not asn_list:
            continue
        try:
            db_client.write_points([{"measurement": _TRAFFIC_MEASUREMENT,
                                     "tags": {'ASN': 'AS{} {} ({})'.format(line_dict['as_dst'], asn_list[1],
                                                                           asn_list[0])},
                                     "fields": {'bytes': line_dict['bytes']}}])
            write_counter += 1
        except (exceptions.InfluxDBClientError, exceptions.InfluxDBServerError) as db_error:
            logger.error('Could not write point to DB: {}'.format(str(db_error)[:-1]))
            logger.error('Exiting...')
            # Canceling Timer thread
            timer_obj.cancel()
            # Sending KeyboardInterrupt to main thread
            interrupt_main()
            break
    logger.debug('Wrote {} points to DB'.format(write_counter))
    data_file.close()


def watch_prefix_file(file_name):
    """ Using inotify function is looking for IN_CLOSE_WRITE events, that happens when pmacct is pushing new data to
        _PMACCT_DATA file. write_to_db is called to store new data into database. On every iteration main thread
        status is checked.
    """
    inotify_obj = Inotify()
    inotify_obj.add_watch(file_name)
    try:
        for event in inotify_obj.event_gen():
            if event is not None:
                if event[1] == ['IN_CLOSE_WRITE']:
                    logger.debug("Found IN_CLOSE_WRITE event")
                    write_to_db()
            else:
                if not main_thread().is_alive():
                    logger.error('Main thread died, stopping all child threads')
                    # Canceling Timer thread
                    timer_obj.cancel()
                    # Breaking watcher thread loop
                    break
    finally:
        inotify_obj.remove_watch(file_name)


def clear_top_talkers_measurement():
    """ On every call ASNs that had highest max bps traffic over last day are chosen and written in
    _TOP_TALKERS_MEASUREMENT, that allows templating in grafana. _TOP_TALKERS_COUNT specifies how many ASNs are stored.
    """
    db_client = InfluxDBClient(_INFLUX_HOST, _INFLUX_PORT, _INFLUX_USERNAME, _INFLUX_PASSWORD, _INFLUX_DATABASE)
    try:
        db_client.delete_series(_INFLUX_DATABASE, _TOP_TALKERS_MEASUREMENT)
        db_client.query('SELECT TOP(bytes,ASN,{}) INTO {} FROM {} WHERE time > now() - 1d'
                        ''.format(_TOP_TALKERS_COUNT, _TOP_TALKERS_MEASUREMENT, _TRAFFIC_MEASUREMENT),
                        database=_INFLUX_DATABASE)
    except (exceptions.InfluxDBClientError, exceptions.InfluxDBServerError) as db_error:
        logger.error('Could not update : {}'.format(db_error))
        logger.error('Exiting...')
        # Canceling Timer thread
        timer_obj.cancel()
        # Sending KeyboardInterrupt to main thread
        interrupt_main()


if __name__ == '__main__':
    try:
        # Starting inotify watcher thread
        watcher = Thread(target=watch_prefix_file, name='prefix_file_watcher', args=(bytes(_PMACCT_DATA, 'utf-8'),))
        watcher.start()
        while main_thread().is_alive():
            current_time = datetime.today()
            # Setting timer for clear_top_talkers_measurement function to 3am each day
            replaced_time = current_time.replace(hour=3, minute=0, second=0, microsecond=0)
            run_time = replaced_time + timedelta(1)
            timer_obj = Timer((run_time - current_time).total_seconds(), clear_top_talkers_measurement)
            timer_obj.name = 'clear_timer'
            timer_obj.start()
            timer_obj.join()
            logger.debug("Cleared top talkers at {}".format(run_time))
    except KeyboardInterrupt:
        logger.error("Main thread received KeyboardInterrupt signal and closed")
        exit(1)
