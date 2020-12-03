#!/usr/bin/env python

import json
import hpfeeds
import sys
import logging
from IPy import IP
from logging.handlers import RotatingFileHandler, SysLogHandler, TimedRotatingFileHandler, WatchedFileHandler
from hpfeeds_output.handlers import cif_handler, bhr_handler
from hpfeeds_output.formatters import splunk, arcsight, json_formatter, raw_json
from hpfeeds_output import processors
from hpfeeds_output import redis_cache

FORMATTERS = {
    'splunk': splunk.SplunkFormatter,
    'arcsight': arcsight.format,
    'json': json_formatter.format,
    'raw_json': raw_json.format
}

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s][%(filename)s] - %(message)s'

logger = logging.getLogger('hpfeeds-output')
logger.setLevel(logging.INFO)
log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(log_handler)

def parse_ignore_cidr_option(cidrlist):
    """
    Given a comma-seperated list of CIDR addresses, split them and validate they're valid CIDR notation
    :param cidrlist: string representing a comma seperated list of CIDR addresses
    :return: a list containing IPy.IP objects representing the ignore_cidr addresses
    """
    l = list()
    for c in cidrlist.split(','):
        try:
            s = c.strip(' ')
            i = IP(s)
            l.append(i)
        except ValueError as e:
            logger.warning('Received invalid CIDR in ignore_cidr: {}'.format(e))
    return l

def main():
    if len(sys.argv) < 2:
        logger.error('No config file found. Exiting')
        return 1

    logger.info('Parsing config file: %s', sys.argv[1])
    with open(sys.argv[1]) as f:
        config = json.load(f)

    if config['debug'] == True:
        logger.setLevel(logging.DEBUG)
        logger.debug('Set logging to DEBUG')
        logger.debug('Parsed config was: {}'.format(config))

    host = config['host']
    port = config['port']
    # hpfeeds protocol has trouble with unicode, hence the utf-8 encoding here
    channels = config['channels']
    ident = config['ident']
    secret = config['secret']

    processor = processors.HpfeedsMessageProcessor()
    logger.debug('HPFeeds Processor: {}'.format(processor.__dict__))
    try:
        formatter = FORMATTERS.get(config['formatter_name'])
    except Exception as e:
        logger.error('Unsupported data log formatter encountered: %s. Exiting.', config['formatter_name'])
        return 1

    data_logger = logging.getLogger('data')
    data_logger.setLevel(logging.INFO)

    try:
        if config['filelog'] and config['filelog']['filelog_enabled']:
            logfile = config['filelog']['log_file']

            if config['filelog']['rotation_backups']:
                backups = int(config['filelog']['rotation_backups'])
            else:
                backups = 3

            if config['filelog']['rotation_strategy'] == 'size':
                max_byt = int(config['filelog']['rotation_size_max']) * 1024 * 1024
                handler = RotatingFileHandler(logfile, maxBytes=max_byt, backupCount=backups)
            elif config['filelog']['rotation_strategy'] == 'time':
                rotation_interval = int(config['filelog']['rotation_time_max'])
                if config['filelog']['rotation_time_unit'] and \
                    config['filelog']['rotation_time_unit'].lower() in ['d', 'h', 'm']:
                    rotation_unit = config['filelog']['rotation_time_unit'].lower()
                else:
                    rotation_unit = 'h'
                    logger.warning('Could not interpret rotation_time_unit; defaulting to hour (h)')
                handler = TimedRotatingFileHandler(logfile, when=rotation_unit,
                                                        interval=rotation_interval, backupCount=backups)
            elif config['filelog']['rotation_strategy'] == 'none':
                handler = WatchedFileHandler(logfile, mode='a')
            else:
                logger.warning('Invalid rotation_strategy! Defaulting to 100 MB size rotation!')
                handler = RotatingFileHandler(logfile, maxBytes=104857600, backupCount=backups)
            #TODO: handle multiple formatter formats
            if config['formatter_name'] == 'splunk':
                handler.setFormatter(splunk.SplunkFormatter())
            data_logger.addHandler(handler)
            logger.info('Writing events to file %s', logfile)
            logger.debug('data_logger currently: {}'.format(data_logger.__dict__))
    except Exception as e:
        logger.error("Invalid file handler arguments: {}".format(e))

    try:
        if config['syslog'] and config['syslog']['syslog_enabled']:
            syslog_host = config['syslog']['syslog_host'] or "localhost"
            syslog_port = config['syslog']['syslog_port'] or 514
            syslog_facility = config['syslog']['syslog_facility'] or "user"
            handler = SysLogHandler(address=(syslog_host, syslog_port), facility=syslog_facility)
            handler.setFormatter(splunk.SplunkFormatter())
            data_logger.addHandler(handler)
            logger.info('Writing events to syslog host %s', syslog_host)
    except Exception:
        logger.error('Invalid sysconfig arguments')

    # BHR / CIFv3 submissions not supported with raw json logs
    if config['formatter_name'] == "raw_json":
        logging.warning("CIFv3 and BHR submissions not supported with raw JSON logs. Ignoring CIFv3 and BHR options")
    else:
        try:
            if config['cif'] and config['cif']['cif_enabled']:
                cif_ignore_list = parse_ignore_cidr_option(config['cif']['cif_ignore_cidr'])
                cif_rcache = redis_cache.RedisCache(host='redis', port=6379, db=4, expire=300)
                cif_host = config['cif']['cif_host']
                cif_token = config['cif']['cif_token']
                cif_provider = config['cif']['cif_provider']
                cif_tlp = config['cif']['cif_tlp']
                cif_confidence = config['cif']['cif_confidence']
                cif_tags = config['cif']['cif_tags'].split(',')
                cif_group = config['cif']['cif_group']
                cif_verify_ssl = config['cif']['cif_verify_ssl']
                handler = cif_handler.CIFv3Handler(host=cif_host, token=cif_token, provider=cif_provider,
                                                   tlp=cif_tlp, confidence=cif_confidence, tags=cif_tags,
                                                   group=cif_group, rcache=cif_rcache,
                                                   ignore_cidr=cif_ignore_list, ssl=cif_verify_ssl)
                data_logger.addHandler(handler)
                logger.info('Writing events to CIFv3 host %s' % cif_host)
        except:
            logger.error("Invalid CIFv3 arguments")

        try:
            if config['bhr'] and config['bhr']['bhr_enabled']:
                bhr_ignore_list = parse_ignore_cidr_option(config['bhr']['bhr_ignore_cidr'])
                bhr_rcache = redis_cache.RedisCache(host='redis', port=6379, db=5, expire=300)
                bhr_host = config['bhr']['bhr_host']
                bhr_token = config['bhr']['bhr_token']
                bhr_source = config['bhr']['bhr_source']
                bhr_reason = config['bhr']['bhr_reason']
                bhr_duration = config['bhr']['bhr_duration']
                bhr_verify_ssl = config['bhr']['bhr_verify_ssl']
                handler = bhr_handler.BHRHandler(host=bhr_host, token=bhr_token, source=bhr_source, reason=bhr_reason,
                                                 duration=bhr_duration, rcache=bhr_rcache, ignore_cidr=bhr_ignore_list,
                                                 ssl=bhr_verify_ssl)
                data_logger.addHandler(handler)
                logger.info('Writing events to BHR host %s' % bhr_host)
        except:
            logger.error("Invalid BHR arguments")

    try:
        hpc = hpfeeds.client.new(host, port, ident, secret)
    except hpfeeds.FeedException as e:
        logger.error('hpfeed exception: {}'.format(e))
        return 1

    logger.info('connected to %s', hpc.brokername)
    logger.debug('HPC: {}'.format(hpc.__dict__))

    def on_message(identifier, channel, payload):
        if config['formatter_name'] == "raw_json":
            data_logger.info(payload.decode('utf8'))
        else:
            for msg in processor.process(identifier, channel, payload.decode('utf-8'), ignore_errors=True):
                logger.debug('Message returned from procesor: {}'.format(msg))
                data_logger.info(json.dumps(msg))

    def on_error(payload):
        logger.error('Error message from server: %s', payload)
        hpc.stop()

    hpc.subscribe(channels)
    try:
        hpc.run(on_message, on_error)
    except hpfeeds.FeedException as e:
        logger.error('feed exception:')
        logger.exception(e)
    except KeyboardInterrupt:
        logger.error('KeyboardInterrupt encountered, exiting ...')
    except Exception as e:
        logger.error('Unknown error encountered, exiting ...')
        logger.exception(e)
    finally:
        hpc.close()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.error('KeyboardInterrupt encountered, exiting ...')
        sys.exit(0)
