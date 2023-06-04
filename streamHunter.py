import requests, sys, socket, argparse, ipaddress, subprocess, tempfile, os
from bs4 import BeautifulSoup
from random import randint
from halo import Halo
from threading import Thread
import png, base64

class terminalColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

normalHeaders = {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0'
}

def printError(txt):
    print('[' + terminalColors.FAIL + terminalColors.BOLD + '-' + terminalColors.ENDC + ']' + txt)

def printSuccess(txt):
    print('[' + terminalColors.OKGREEN + terminalColors.BOLD + '+' + terminalColors.ENDC + ']' + txt)

def obtainMac(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'helo', (ip, randint(10000, 65535)))
        sock.close()
    except:
        pass
    f = open('/proc/net/arp', 'r')
    contents = f.read()
    f.close()
    for l in contents.split('\n')[1:]:
        clean = []
        for p in l.split(' '):
            if len(p) > 0:
                clean.append(p)
        if len(clean) != 6:
            continue
        addr, whType, flags, hwAddr, mask, dev = clean
        if addr == ip:
            return hwAddr.upper()
    return None

def scanPort(ip, p, l):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((ip, p))
    if result == 0:
        l.append(p)
    s.close()

def filterClues(el, bannedWords):
    for e in bannedWords:
        if e in el:
            return False 
    return True

def testRTSP(uri):
    out = tempfile.mktemp() + '.png'
    try:
        subprocess.Popen(['ffmpeg', '-y', '-i', uri, '-vframes', '1', out])
    except:
        pass
    if not os.path.exists(out):
        return False
    else:
        try:
            r = png.Reader(file=open(out, 'rb'))
            r.read()
        except Exception as e:
            print(e)
            return False

def testHTTPStreaming(user, password, ip, port, path):
    try:
        r = requests.get('http://{}:{}@{}:{}{}'.format(user, password, ip, port, ('/' + path) if not path.startswith('/') else path), stream=True)
        if r.status_code == 200:
            return r.url
        else:
            raise Exception('http not working')
    except:
        try:
            r = requests.get('https://{}:{}@{}:{}{}'.format(user, password, ip, port, ('/' + path) if not path.startswith('/') else path), stream=True)
            if r.status_code == 200:
                return r.url
            else:
                return None
        except:
            return None

parser = argparse.ArgumentParser(
    prog='streamhunter',
    description='Automatically find the streaming URL for a specific IP Camera'
)

parser.add_argument('--ip',  required=True, type=str, help='The IP Camera address')

group = parser.add_mutually_exclusive_group(required=True)

group.add_argument('--default-credentials', dest='defaultCredentials', nargs='?', default=argparse.SUPPRESS, help='Tries to authenticate using a list of commonm default credentials')

group.add_argument('--user', type=str, help='The user to use to authenticate')

parser.add_argument('--password', type=str, help='The password to use to authenticate', required= '--user' in sys.argv)

print(terminalColors.BOLD + terminalColors.OKBLUE + """
     ┌───────────┐
     │ ▒▒▒▒▒▒▒▒  │──┐     ____  _                              _   _             _            
     │           │──┘    / ___|| |_ _ __ ___  __ _ _ __ ___   | | | |_   _ _ __ | |_ ___ _ __ 
     └───┬───┬───┘       \___ \| __| '__/ _ \/ _` | '_ ` _ \  | |_| | | | | '_ \| __/ _ \ '__|
    ├────┘   │            ___) | |_| | |  __/ (_| | | | | | | |  _  | |_| | | | | ||  __/ | 
    ├────────┘           |____/ \__|_|  \___|\__,_|_| |_| |_| |_| |_|\__,_|_| |_|\__\___|_|  

""" + terminalColors.ENDC)                                                                 

args = parser.parse_args()

try:
    if (ipaddress.ip_address(args.ip).version != 4):
        raise Exception("Ip must be an IPv4")
except:
    sys.exit("Error:\nInvalid IP: {}".format(args.ip))

print('Gathering clues about {}...'.format(args.ip))

clues = []

try:
    hostname = socket.gethostbyaddr(args.ip)[0]
    clues.append(hostname)
    printSuccess('Obtained hostname ({})'.format(hostname))
except:
    printError('Failed to obtain hostname')

mac = obtainMac(args.ip)

if (mac is not None):
    macInfo = requests.get('https://api.maclookup.app/v2/macs/' + mac).json()
    printSuccess('Obtained mac address info (Address: {}, Company: {})'.format(mac, macInfo['company']))
    clues.extend(macInfo['company'].lower().split(' '))
else:
    printError('Failed to obtain MAC address from ip')

spinner = Halo(text='Scanning ports...', spinner='dots')
spinner.start()

openPorts = []

threads = []

for port in range(1, 65535):
    t = Thread(target=scanPort, args=(args.ip, port, openPorts), daemon=True)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

spinner.stop()
printSuccess('Open ports:\n{}'.format('\n'.join([ '\t- ' + str(e) + '/tcp' for e in openPorts ])))

webInterfaces = []

spinner.text = 'Fetching clues from webpages...'
spinner.start()

for p in openPorts:
    r = None
    try:
        r = requests.get('http://{}:{}/'.format(args.ip, p), headers=normalHeaders, timeout=3)
    except Exception as e:
        try:
            r = requests.get('https://{}:{}/'.format(args.ip, p),
                                                        headers=normalHeaders,
                                                        timeout=3,
                                                        verify=False)
        except Exception as e:
            continue

    if r.status_code == 200 and 'content-type' in r.headers and 'text/html' in r.headers['content-type']:
        webInterfaces.append(r.url)
        s = BeautifulSoup(r.text, 'xml')
        title = s.find('title')
        if title is not None:
            clues.extend(title.text.lower().split(' '))

spinner.stop()

if len(webInterfaces) > 0:
    printSuccess('Detected web UI\'s:\n{}'.format('\n'.join([ '\t- ' + e for e in webInterfaces ])))

spinner.text = 'Attempting to fetch connection strings using ONVIF...'
spinner.start()

getProfilesPayload = """
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdl="http://www.onvif.org/ver10/media/wsdl">
  <soap:Header/>
  <soap:Body>
    <wsdl:GetProfiles/>
   </soap:Body>
</soap:Envelope>
"""

getProfilesHeaders = {
    'Content-Type': 'application/soap+xml; charset=utf-8',
    'SOAPAction': '"http://www.onvif.org/ver10/media/wsdl/GetProfiles"'
}

onvifURLs = []

for p in openPorts:
    r = None
    https = False
    try:
        r = requests.post('http://{}:{}/{}'.format(args.ip, p, 'onvif/device_service'), data=getProfilesPayload, headers=getProfilesHeaders, timeout=3)
    except Exception as e:
        try:
            r = requests.post('https://{}:{}/{}'.format(args.ip, p, 'onvif/device_service'), 
                                                        data=getProfilesPayload,
                                                        headers=getProfilesHeaders,
                                                        timeout=3,
                                                        verify=False)
            https = True
        except Exception as e:
            pass
        
    if r is not None and r.status_code == 200:
        soup = BeautifulSoup(r.text, 'xml')
        for e in soup.select('[token]'):
            token = e.attrs['token']
            payload = """
            <soap:Envelope
            xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsdl="http://www.onvif.org/ver10/media/wsdl"
            >
            <soap:Header/>
            <soap:Body>
                <wsdl:GetStreamUri>
                <wsdl:ProfileToken>{}</wsdl:ProfileToken>
                </wsdl:GetStreamUri>
            </soap:Body>
            </soap:Envelope>
            """.format(token)
            r = requests.post('{}://{}:{}/{}'.format('https' if https else 'http', args.ip, p, 'onvif/device_service'), 
                                                     data=payload,
                                                     headers={
                                                         'Content-Type': 'application/soap+xml; charset=utf-8',
                                                         'SOAPAction': '"http://www.onvif.org/ver10/media/wsdl/GetStreamUri"'
                                                     },
                                                     timeout=3,
                                                     verify=False)
            uriSoup = BeautifulSoup(r.text, 'xml')
            for uri in uriSoup.find_all('tt:Uri'):
                onvifURLs.append(uri.text)

onvifURLs = list(set(onvifURLs))

spinner.stop()

if len(onvifURLs) > 0:
    printSuccess('URL\'s found:\n{}'.format('\n'.join([ '\t- ' + str(e) for e in onvifURLs ])))
else:
    printError('No URL\'s found using ONVIF')

clues = list(filter(lambda e: filterClues(e, ['inc', 'corp', 'technology', 'web', 'cctv', 'service', 'ltd']), clues))

spinner.text = 'Fetching camera makes...'
spinner.start()

modelsPage =  requests.get('https://www.ispyconnect.com/cameras', headers = normalHeaders)

modelsSoup = BeautifulSoup(modelsPage.text, features='lxml')

index = [ e.text for e in modelsSoup.find_all('th', attrs= { 'valign': 'top' }) ]

cameraMakes = []

for l in index:
    makesPage =  requests.get('https://www.ispyconnect.com/cameras/{}'.format(l), headers = normalHeaders)
    s = BeautifulSoup(makesPage.text, features='lxml')
    cameraMakes.extend([ ( e.text.lower(), e.attrs['href'] ) for e in s.find('td').find_all('a') ])

spinner.stop()

modelsPage =  requests.get('https://www.ispyconnect.com/cameras', headers = normalHeaders)

if (modelsPage.status_code != 200):
    printError('ispyconnect.com is now probably blocking the requests')
    sys.exit(1)

modelsSoup = BeautifulSoup(modelsPage.text, features='lxml')

cameraMakes = [ (e.text.lower(), e.attrs['href']) for e in modelsSoup.body.find('table').find_all('a') ]

printSuccess('Fetched camera makes')

validURLs = []

defaultCredentials = [
    ('admin', 'admin'),
    ('admin', '1234'),
    ('Admin', '1234'),
    ('admin', '12345'),
    ('admin', '123456'),
    ('admin', '9999'),
    ('root', 'root'),
    ('888888', '888888'),
    ('666666', '666666'),
    ('admin', 'fliradmin'),
    ('administrator', '1234'),
    ('root', 'system'),
    ('root', 'camera'),
    ('root', 'admin'),
    ('admin', 'jvc'),
    ('root', 'ikwd'),
    ('root', 'ikwb'),
    ('supervisor', 'supervisor'),
    ('ubnt', 'ubnt'),
    ('admin', 'wbox123'),
    ('admin', '4321'),
    ('admin', '1111111'),
]

for make, link in cameraMakes:
    for c in clues:
        if make in c:
            printSuccess('Identified possible camera make ({})...'.format(make))

            spinner.text = 'Fetching connection strings..'
            spinner.start()

            urlsPage =  requests.get('https://www.ispyconnect.com/' + link, headers = normalHeaders)

            urlsSoup = BeautifulSoup(urlsPage.text, features='lxml')

            cameraUrlsRaw = [ e.find_all('td') for e in urlsSoup.body.find('table').find_all('tr') ]

            cameraUrls = []

            for e in cameraUrlsRaw:
                if len(e) == 4:
                    cameraUrls.append((e[0].text.split(', '), e[1].text, e[2].text.lower(), e[3].text))

            spinner.stop()

            printSuccess('Fetched connection strings for {}'.format(make))

            spinner.text = 'Testing the connection strings\'s...'
            spinner.start()

            for models, streamType, protocol, path in cameraUrls:
                path = path.replace('[CHANNEL]', '0')
                path = path.replace('[WIDTH]', '320')
                path = path.replace('[HEIGHT]', '240')
                if 'rtsp' in protocol:
                    if 'defaultCredentials' in args:
                        for user, password in defaultCredentials:
                            path = path.replace('[USERNAME]', user)
                            path = path.replace('[PASSWORD]', password)
                            path = path.replace('[AUTH]', base64.b64encode('{}:{}'.format(user, password).encode('utf-8')).decode('utf-8'))
                            url = 'rtsp://{}:{}@{}{}'.format(user, password, args.ip, ('/' + path) if not path.startswith('/') else path)
                            if testRTSP(url):
                                validURLs.append(url)
                    else:
                        path = path.replace('[USERNAME]', args.user)
                        path = path.replace('[PASSWORD]', args.password)
                        path = path.replace('[AUTH]', base64.b64encode('{}:{}'.format(args.user, args.password).encode('utf-8')).decode('utf-8'))
                        url = 'rtsp://{}:{}@{}{}'.format(args.user, args.password, args.ip, ('/' + path) if not path.startswith('/') else path)
                        if testRTSP(url):
                            validURLs.append(url)
                elif 'http' in protocol:
                    if 'defaultCredentials' not in args:
                        for user, password in defaultCredentials:
                            path = path.replace('[USERNAME]', user)
                            path = path.replace('[PASSWORD]', password)
                            path = path.replace('[AUTH]', base64.b64encode('{}:{}'.format(user, password).encode('utf-8')).decode('utf-8'))
                            for p in openPorts:
                                url = testHTTPStreaming(user, password, args.ip, p, path)
                                if (url is not None):
                                    validURLs.append(url)
                    else:
                        path = path.replace('[USERNAME]', args.user)
                        path = path.replace('[PASSWORD]', args.password)
                        path = path.replace('[AUTH]', base64.b64encode('{}:{}'.format(args.user, args.password).encode('utf-8')).decode('utf-8'))
                        for p in openPorts:
                               url = testHTTPStreaming(args.user, args.password, args.ip, p, path)
                               if (url is not None):
                                   validURLs.append(url) 

            spinner.stop()


printSuccess('URL\'s found:\n{}'.format('\n'.join([ '\t- ' + e for e in validURLs ])))



print('Done')