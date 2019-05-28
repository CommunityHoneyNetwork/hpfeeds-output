#!/usr/bin/env python

import json
import hpfeeds
import sys
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
from hpfeeds_output.handlers import cif_handler, bhr_handler
from hpfeeds_output.formatters import splunk, arcsight, json_formatter, raw_json
from hpfeeds_output import processors


FORMATTERS = {
    'splunk': splunk.SplunkFormatter,
    'arcsight': arcsight.format,
    'json': json_formatter.format,
    'raw_json': raw_json.format
}

log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)


def main():
    if len(sys.argv) < 2:
        logger.error('No config file found. Exiting')
        return 1

    logger.info('Parsing config file: %s', sys.argv[1])

    config = json.load(file(sys.argv[1]))
    host = config['host']
    port = config['port']
    # hpfeeds protocol has trouble with unicode, hence the utf-8 encoding here
    channels = [c.encode('utf-8') for c in config['channels']]
    ident = config['ident'].encode('utf-8')
    secret = config['secret'].encode('utf-8')

    processor = processors.HpfeedsMessageProcessor()
    formatter = FORMATTERS.get(config['formatter_name'])
    if not formatter:
        logger.error('Unsupported data log formatter encountered: %s. Exiting.', config['formatter_name'])
        return 1

    data_logger = logging.getLogger('data')
    data_logger.setLevel(logging.INFO)

    try:
        if config['filelog'] and config['filelog']['filelog_enabled']:
            logfile = config['filelog']['log_file']
            handler = RotatingFileHandler(logfile, maxBytes=100 * 1024 * 1024, backupCount=3)
            handler.setFormatter(splunk.SplunkFormatter())
            data_logger.addHandler(handler)
            logger.info('Writing events to %s', logfile)
    except Exception:
        logger.error("Invalid file handler arguments")

    try:
        if config['syslog'] and config['syslog']['syslog_enabled']:
            syslog_host = config['syslog']['syslog_host'] or "localhost"
            syslog_port = config['syslog']['syslog_port'] or 514
            syslog_facility = config['syslog']['syslog_facility'] or "user"
            handler = SysLogHandler(address=(syslog_host, syslog_port), facility=syslog_facility)
            handler.setFormatter(splunk.SplunkFormatter())
            data_logger.addHandler(handler)
            logger.info('Writing syslog events to %s', syslog_host)
    except Exception:
        logger.error('Invalid sysconfig arguments')

    # BHR / CIFv3 submissions not supported with raw json logs
    if config['formatter_name'] == "raw_json":
        logging.warning("CIFv3 and BHR submissions not supported with raw JSON logs.")
    else:
        try:
            if config['cif'] and config['cif']['cif_enabled']:
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
                                                   group=cif_group, ssl=cif_verify_ssl)
                data_logger.addHandler(handler)
                logger.info('Writing CIFv3 events to %s' % cif_host)
        except:
            logger.error("Invalid CIFv3 arguments")

        try:
            if config['bhr'] and config['bhr']['bhr_enabled']:
                bhr_host = config['bhr']['bhr_host']
                bhr_token = config['bhr']['bhr_token']
                bhr_source = config['bhr']['bhr_source']
                bhr_reason = config['bhr']['bhr_reason']
                bhr_duration = config['bhr']['bhr_duration']
                bhr_verify_ssl = config['bhr']['bhr_verify_ssl']
                handler = bhr_handler.BHRHandler(host=bhr_host, token=bhr_token, source=bhr_source, reason=bhr_reason,
                                                 duration=bhr_duration, ssl=bhr_verify_ssl)
                data_logger.addHandler(handler)
                logger.info('Writing BHR events to %s' % bhr_host)
        except:
            logger.error("Invalid BHR arguments")

    try:
        hpc = hpfeeds.new(host, port, ident, secret)
    except hpfeeds.FeedException as e:
        logger.error('feed exception', e)
        return 1

    logger.info('connected to %s', hpc.brokername)

    def on_message(identifier, channel, payload):
        if config['formatter_name'] == "raw_json":
            data_logger.info(payload)
        else:
            for msg in processor.process(identifier, channel, payload, ignore_errors=True):
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
