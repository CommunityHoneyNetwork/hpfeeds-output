import os
import json
import uuid

from hpfeeds.add_user import create_user


def get_bool(bool_str):
    if bool_str.lower() == "true":
        return True
    return False


def main():
    print("Starting build_config.py")
    DEBUG = os.environ.get("DEBUG", "false")
    MONGODB_HOST = os.environ.get("MONGODB_HOST", "mongodb")
    MONGODB_PORT = os.environ.get("MONGODB_PORT", "27017")

    HPFEEDS_HOST = os.environ.get("HPFEEDS_HOST", "hpfeeds3")
    HPFEEDS_PORT = os.environ.get("HPFEEDS_PORT", "10000")
    IDENT = os.environ.get("IDENT", "hpfeeds-logger")
    SECRET = os.environ.get("SECRET", "")
    CHANNELS = os.environ.get("CHANNELS", "amun.events,conpot.events,thug.events,beeswarm.hive,dionaea.capture,dionaea.connections,thug.files,beeswarm.feeder,cuckoo.analysis,kippo.sessions,cowrie.sessions,glastopf.events,glastopf.files,mwbinary.dionaea.sensorunique,snort.alerts,wordpot.events,p0f.events,suricata.events,shockpot.events,elastichoney.events,rdphoney.sessions,uhp.events,elasticpot.events,spylex.events,big-hp.events,ssh-auth-logger.events,honeydb-agent.events")
    FORMATTER_NAME = os.environ.get("FORMATTER_NAME", "splunk")
    FILELOG_ENABLED = os.environ.get("FILELOG_ENABLED", "false")
    LOG_FILE = os.environ.get("LOG_FILE", "/data/chn-splunk.log")

    SYSLOG_ENABLED = os.environ.get("SYSLOG_ENABLED", "false")
    SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "localhost")
    SYSLOG_PORT = os.environ.get("SYSLOG_PORT", "514")
    SYSLOG_FACILITY = os.environ.get("SYSLOG_FACILITY", "USER")

    ROTATION_STRATEGY = os.environ.get("ROTATION_STRATEGY", "size")
    ROTATION_SIZE_MAX = os.environ.get("ROTATION_SIZE_MAX", "100")
    ROTATION_TIME_MAX = os.environ.get("ROTATION_TIME_MAX", "24")
    ROTATION_TIME_UNIT = os.environ.get("ROTATION_TIME_UNIT", "h")

    CIF_ENABLED=os.environ.get("CIF_ENABLED", "false")
    CIF_HOST=os.environ.get("CIF_HOST", "")
    CIF_TOKEN=os.environ.get("CIF_TOKEN", "")
    CIF_PROVIDER=os.environ.get("CIF_PROVIDER", "")
    CIF_TLP=os.environ.get("CIF_TLP", "")
    CIF_CONFIDENCE=os.environ.get("CIF_CONFIDENCE", "")
    CIF_TAGS=os.environ.get("CIF_TAGS", "")
    CIF_GROUP=os.environ.get("CIF_GROUP", "")
    CIF_IGNORE_CIDR=os.environ.get("CIF_IGNORE_CIDR","192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
    CIF_VERIFY_SSL=os.environ.get("CIF_VERIFY_SSL", "")

    BHR_ENABLED=os.environ.get("BHR_ENABLED", "false")
    BHR_HOST=os.environ.get("BHR_HOST", "")
    BHR_TOKEN=os.environ.get("BHR_TOKEN", "")
    BHR_SOURCE=os.environ.get("BHR_SOURCE", "chn")
    BHR_DURATION=os.environ.get("BHR_DURATION", "3600")
    BHR_IGNORE_CIDR=os.environ.get("BHR_IGNORE_CIDR","192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
    BHR_VERIFY_SSL=os.environ.get("BHR_VERIFY_SSL", "false")


    config_template = open("/opt/hpfeeds-output/output.json.example", 'r')

    if SECRET:
        secret = SECRET
    else:
        secret = str(uuid.uuid4()).replace("-", "")

    channels = CHANNELS.split(",")

    # Configure hpfeeds settings
    config = json.loads(config_template.read())
    config['host'] = HPFEEDS_HOST
    config['port'] = int(HPFEEDS_PORT)
    config['ident'] = IDENT
    config['secret'] = secret
    config['channels'] = channels
    config['debug'] = get_bool(DEBUG)
    config['formatter_name'] = FORMATTER_NAME

    # Configure filelog settings
    config['filelog']['filelog_enabled'] = get_bool(FILELOG_ENABLED)
    config['filelog']['log_file'] = LOG_FILE
    config['filelog']['rotation_strategy'] = ROTATION_STRATEGY
    config['filelog']['rotation_size_max'] = int(ROTATION_SIZE_MAX)
    config['filelog']['rotation_time_max'] = int(ROTATION_TIME_MAX)
    config['filelog']['rotation_time_unit'] = ROTATION_TIME_UNIT

    # Configure syslog settings
    config['syslog']['syslog_enabled'] = get_bool(SYSLOG_ENABLED)
    config['syslog']['syslog_host'] = SYSLOG_HOST
    config['syslog']['syslog_port'] = int(SYSLOG_PORT)
    config['syslog']['syslog_facility'] = SYSLOG_FACILITY

    config['cif']['cif_enabled'] = get_bool(CIF_ENABLED)
    config['cif']['cif_host'] = CIF_HOST
    config['cif']['cif_token'] = CIF_TOKEN
    config['cif']['cif_provider'] = CIF_PROVIDER
    config['cif']['cif_tlp'] = CIF_TLP
    config['cif']['cif_confidence'] = CIF_CONFIDENCE
    config['cif']['cif_tags'] = CIF_TAGS
    config['cif']['cif_group'] = CIF_GROUP
    config['cif']['cif_ignore_cidr'] = CIF_IGNORE_CIDR
    config['cif']['cif_verify_ssl'] = get_bool(CIF_VERIFY_SSL)

    config['bhr']['bhr_enabled'] = get_bool(BHR_ENABLED)
    config['bhr']['bhr_host'] = BHR_HOST
    config['bhr']['bhr_token'] = BHR_TOKEN
    config['bhr']['bhr_source'] = BHR_SOURCE
    config['bhr']['bhr_duration'] = BHR_DURATION
    config['bhr']['bhr_ignore_cidr'] = BHR_IGNORE_CIDR
    config['bhr']['bhr_verify_ssl'] = get_bool(BHR_VERIFY_SSL)

    print("Writing config...")

    with open("/data/config/output.json", 'w') as config_file:
        config_file.write(json.dumps(config))

    create_user(host=MONGODB_HOST, port=int(MONGODB_PORT), owner="chn",
                ident=IDENT, secret=secret, publish="", subscribe=CHANNELS)


if __name__ == "__main__":
    main()
