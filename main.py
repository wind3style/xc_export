import logging
import requests
import re
import json
import sys
import os.path
import pandas as pd
import configparser
import time

class MAIN_EXCEPTION(Exception):
    pass

class CONFIG_EXCEPTION(Exception):
    pass

class Config_account:
    def __init__(self, name):
        self.name = name
        self.login = None
        self.password=  None


class Config:
    def __init__(self):
        self.src = None
        self.date=  None
        self.country = None
        self.username_table = {}
        self.http_debug = False
        self.log_level = 'DEBUG'
        self.key = '03ECF5952EB046AC-A53195E89B7996E4-D1B128E82C3E2A66'
        self.lng = 'en'
        self.accounts = list()
        self.account_inx = None
        self.track_dir = None
        self.attendence_list_file = None
        self.http_retry_sleep=20
        self.http_retry_count=2
        self.log_file = None

config = Config()
sess = None

def main():
    global sess

    try:
        read_config('xc_export_conf.ini')

        log_args =  {'level': config.log_level, 'encoding': 'utf-8', 'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s', 'handlers': [ logging.StreamHandler() ]}

        if config.log_file != None:
            log_args['handlers'].append(logging.FileHandler(config.log_file, mode='a', encoding='utf-8'))

        logging.basicConfig(**log_args)
        logging.info('XCTrack fly log exporter')

        read_attendence_list()

        http_sess_init()

        flights = XC_flights_fillter(config.src, config.date, config.country)
        logging.info('Got list of flights: %d'%(len(flights)))
        logging.debug('Flights:')
        logging.debug(json.dumps(flights, indent=4))
        for flight in flights:
            if flight['pilot']['username'] in config.username_table:
                xc_user = config.username_table[flight['pilot']['username']]
                name = flight['pilot']['name']
                logging.info(f'Pilot "{name}" selected')
                    ### get flight IGC
                src = config.src
                flight_id = flight['id']
                key = config.key
                lng = config.lng
                url = f'https://www.xcontest.org/api/data/?flights/{src}:{flight_id}&lng={lng}&key={key}'
                details = http_req_get_json(url)
                logging.info(f'Got flight details for "{name}"')
                logging.debug(f'Flight details:')
                logging.debug(json.dumps(details, indent=4))
                igc_data = http_req_get_binary(details['igc']['link'])
                logging.info(f'Got IGC track for "{name}"')
                igc_file_path = os.path.join(config.track_dir, make_igc_file_name(xc_user, details))
                with open(igc_file_path, "wb") as fout:
                    fout.write(igc_data)

    except MAIN_EXCEPTION as e:
        logging.error(f'main error: ' + str(e))


def read_config(file_name):
    global config
    try:
        cParser = configparser.ConfigParser()
        f = open(file_name)
        cParser.read_file(f)

        get_param(cParser, 'MAIN', 'src', config, 'src', str, True)
        get_param(cParser, 'MAIN', 'date', config, 'date', str, True)
        get_param(cParser, 'MAIN', 'country', config, 'country', str, True)
        get_param(cParser, 'MAIN', 'http_debug', config, 'http_debug', bool, False)
        get_param(cParser, 'MAIN', 'log_level', config, 'log_level', str, False)
        get_param(cParser, 'MAIN', 'key', config, 'key', str, False)
        get_param(cParser, 'MAIN', 'lng', config, 'lng', str, False)
        get_param(cParser, 'MAIN', 'track_dir', config, 'track_dir', str, True)
        get_param(cParser, 'MAIN', 'attendence_list_file', config, 'attendence_list_file', str, True)

        get_param(cParser, 'MAIN', 'http_retry_sleep', config, 'http_retry_sleep', int, False)
        get_param(cParser, 'MAIN', 'http_retry_count', config, 'http_retry_count', int, False)
        get_param(cParser, 'MAIN', 'log_file', config, 'log_file', str, False)

        if config.log_level not in ['DEBUG', 'INFO', 'ERROR']:
            raise MAIN_EXCEPTION('Incorrect log_level value: "%s"'%(config.log_level))

        for section in cParser.sections():
            if section.startswith('ACCOUNT:'):
                account_name = section[8:]
                conf_account = Config_account(account_name)
                get_param(cParser, section, 'login', conf_account, 'login', str, True)
                get_param(cParser, section, 'password', conf_account, 'password', str, True)
                config.accounts.append(conf_account)
                print('Add account login: %s'%(conf_account.login))

    except Exception as e:
        logging.error(f'config error: ' + str(e))
        sys.exit(1)

'''
details:
"ident": "mshpadi/24.07.2023/05:52"
'''
def make_igc_file_name(xc_user, details):
    ident = details['ident']
    logging.debug(f'make_igc_file_name: Ident: "{ident}"')
    m = re.match(r'^(.*)\/(\d{2})\.(\d{2})\.(\d{4})\/(\d{2})\:(\d{2})$', ident)
    if m != None:
        login = m.group(1)
        DD = m.group(2)
        MM = m.group(3)
        YYYY = m.group(4)
        H24 = m.group(5)
        MI = m.group(6)
        SEC = '00'
        file_name = xc_user['name'] + '.' + f'{YYYY}{MM}{DD}-{H24}{MI}{SEC}' + '.' + '[CIVLID]' + '.' + str(xc_user['number']) + '.igc'
        logging.info(f'track file name: "{file_name}"')
        return file_name
    else:
        raise MAIN_EXCEPTION(f'Incorrect format ident: {ident}')


def XC_flights_fillter(src, date, country):
    global sess

    url = f'https://www.xcontest.org/api/data/?flights/{src}'

    params = {
            'lng': config.lng,
            'key': config.key,
            'google_maps_api_key': 'null',
            'callback': 'window.top.ZenController._callJSONP',
            'params[]': 'd002d4fc16ebc1833e6702cce8ede488',
            'list[sort]': 'reg',
            'list[start]': '0',
            'list[num]': '100',
            'list[dir]': 'down',
            'filter[date]': date,
            'filter[country]': country}

    content = http_req_get(url, params=params)
    m = re.search(r'window.top.ZenController._callJSONP\((.*),(.*)\)', content)
    if m != None:
        logging.debug('JSON: %s'% (m.group(1)))
        flights = json.loads(m.group(1))
        return flights['items']
    else:
        raise MAIN_EXCEPTION("Response parsing error")

def http_sess_init():
    global sess

    if config.http_debug == True:
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1

        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    sess = requests.Session()
    sess.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'})
    sess.headers.update({'Accept': '*/*'})
    sess.headers.update({'Accept-Encoding': 'gzip, deflate, br'})
    sess.headers.update({'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7,tr;q=0.6,bg;q=0.5,fr-FR;q=0.4,fr;q=0.3'})
    sess.headers.update({'Referer': 'https://www.xcontest.org/blank.html'})
    sess.headers.update({'Sec-Fetch-Dest': 'script'})
    sess.headers.update({'Sec-Fetch-Mode': 'no-cors'})
    sess.headers.update({'Sec-Fetch-Site': 'same-origin'})
    sess.headers.update({'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"'})
    sess.headers.update({'sec-ch-ua-mobile': '?0'})
    sess.headers.update({'sec-ch-ua-platform': '"Windows"'})

        ### select account
    if len(config.accounts) == 0:
        raise MAIN_EXCEPTION("No one account defined")

    if config.account_inx == None:
        config.account_inx = 0
    else:
        config.account_inx += 1

    logging.info("Select account: inx: %d"%(config.account_inx))

    if config.account_inx >= len(config.accounts):
        logging.info("Account is finished, account_inx = 0")
        config.account_inx = 0

    conf_account = config.accounts[config.account_inx]

    resp = sess.post('https://www.xcontest.org/world/en/', data={'login[username]': conf_account.login, 'login[password]': conf_account.password})
    logging.debug('HTTP resp status code: %s' % (resp.status_code))
    logging.debug('HTTP resp content: %s' % (resp.content))
    if resp.status_code != 200:
        raise MAIN_EXCEPTION("Incorrect HTTP status code: %s" % (resp.status_code))
    content = resp.content.decode('utf-8')
    if 'Username or password you have entered is not valid' in content:
        logging.error('"Username or password you have entered is not valid"')
        sys.exit(1)

    logging.info('Successful login: %s' % (conf_account.login))

def http_req_get_json(url, **kwargs):
    try:
        json_string = http_req_get(url, **kwargs)
        return json.loads(json_string)
    except Exception as e:
        raise MAIN_EXCEPTION("Incorrect JSON, exception: '%s', JSON: '%s'"%(str(e), json_string))

def http_req_get(url, **kwargs):
    return http_req_get_binary(url, **kwargs).decode('utf-8')

def http_req_get_binary(url, **kwargs):
    for i in range(config.http_retry_count):
        resp = sess.get(url, **kwargs)
        if resp.status_code == 200:
            logging.debug('HTTP resp status code: %s' % (resp.status_code))
            logging.debug('HTTP resp content: %s' % (resp.content))
        else:
            logging.info('HTTP resp status code: %s' % (resp.status_code))
            logging.info('HTTP resp content: %s' % (resp.content))

        if resp.status_code in [450, 429]:
            http_sess_init()
            if config.account_inx == 0:
                logging.warning('HTTP resp status code: %s, URL: %s - sleep %d sec and retry' % (resp.status_code, url, config.http_retry_sleep))
                time.sleep(config.http_retry_sleep)
            continue

        if resp.status_code == 200:
            return resp.content
        else:
            raise MAIN_EXCEPTION("Incorrect HTTP status code: %s , content: '%s'"% (resp.status_code, str(resp.content)))

    raise MAIN_EXCEPTION("Excceed max time attempts")

def read_attendence_list():
    global config

    df = pd.read_excel(
        config.attendence_list_file,
        engine='openpyxl'
    )
    logging.info("Attendence list:\n" + str(df))
    row_num = 0
    while(True):
        try:
            login = df['Login'][row_num]
            number = df['Number'][row_num]
            name = df['Name'][row_num]
            logging.debug(f'Login: "{login}", \tNumber: "{number}", \tName: "{name}"')
            config.username_table[login] = {'number': number, 'name': name}
            row_num += 1
        except KeyError:
            break

def get_param(cParser, section, object_var_name, conf_obj, param_name, param_type=str, mantatory_flag=True):
    if cParser == None:
        raise CONFIG_EXCEPTION("Incorrect use get_param()")
    if cParser.has_option(section, param_name):
        if param_type == bool:
            val = cParser[section].getboolean(param_name)
        else:
            val = cParser[section][param_name]
            if type(val) != param_type:
                if param_type == int:
                    try:
                        val = int(val)
                    except Exception as e:
                        raise CONFIG_EXCEPTION("Incorrect parameter value for %s:%s - %s"%(section, param_name, str(e)))
                else:
                    raise CONFIG_EXCEPTION("Unknow parameter type for %s:%s"%(section, param_name))

        setattr(conf_obj, object_var_name, val)
    else:
        if mantatory_flag:
            raise CONFIG_EXCEPTION("Error config: " + "[" + section +"]." + param_name +" MUST be defined")

if __name__ == '__main__':
    main()