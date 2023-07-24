import logging
import requests
import re
import json
import sys
import os.path

class Config:
    def __init__(self):
        self.src = 'world/2023'
        self.date=  '2023-07-24'
        self.country = 'KZ'
        self.username_table = {'mshpadi': None}
        self.http_debug = False
        self.log_level = 'DEBUG'
        self.key = '03ECF5952EB046AC-A53195E89B7996E4-D1B128E82C3E2A66'
        self.lng = 'en'
        self.login = 'wind3style'
        self.password = 'CdEdd8wk1sYk'
        self.igc_dir = 'd:\Trash\#863 XC Export'

config = Config()
sess = None

def main():
    global sess
    logging.basicConfig(level=config.log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.info('XCTrack fly log exporter')

    http_sess_init()

    flights = XC_flights_fillter(config.src, config.date, config.country)
    logging.info('Flights:')
    logging.info(json.dumps(flights, indent=4))
    for flight in flights:
        if flight['pilot']['username'] in config.username_table:
            name = flight['pilot']['name']
            logging.info(f'Pilot "{name}" selected')
                ### get flight IGC
            src = config.src
            flight_id = flight['id']
            key = config.key
            lng = config.lng
            url = f'https://www.xcontest.org/api/data/?flights_/{src}:{flight_id}&lng={lng}&key={key}'
            details = http_req_get_json(url)
            logging.info(f'Flight details:')
            logging.info(json.dumps(details, indent=4))
            igc_data = http_req_get_binary(details['igc']['link'])
            igc_file_path = os.path.join(config.igc_dir, name + ".igc")
            with open(igc_file_path, "wb") as fout:
                fout.write(igc_data)

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
        raise Exception("Response parsing error")

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
#    sess.headers.update({'Cookie': 'AStat=N; PHPSESSID=3d9725a1cd711e314818e84acaa8ac6a'})

    resp = sess.post('https://www.xcontest.org/world/en/', data={'login[username]': config.login, 'login[password]': config.password})
    logging.debug('HTTP resp status code: %s' % (resp.status_code))
    logging.debug('HTTP resp content: %s' % (resp.content))
    if resp.status_code != 200:
        raise Exception("Incorrect HTTP status code: %s" % (resp.status_code))
    content = resp.content.decode('utf-8')
    if 'Username or password you have entered is not valid' in content:
        logging.error('"Username or password you have entered is not valid"')
        sys.exit(1)
def http_req_get_json(url, **kwargs):
    return json.loads(http_req_get(url, **kwargs))

def http_req_get(url, **kwargs):
    return http_req_get_binary(url, **kwargs).decode('utf-8')

def http_req_get_binary(url, **kwargs):
    resp = sess.get(url, **kwargs)
    logging.debug('HTTP resp status code: %s' % (resp.status_code))
    logging.debug('HTTP resp content: %s' % (resp.content))
    if resp.status_code == 200:
        return resp.content
    else:
        raise Exception("Incorrect HTTP status code: %s" % (resp.status_code))


if __name__ == '__main__':
    main()