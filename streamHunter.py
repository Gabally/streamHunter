import requests, sys, socket, argparse, ipaddress
from bs4 import BeautifulSoup
from random import randint
from halo import Halo
from threading import Thread

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

parser = argparse.ArgumentParser(
    prog='streamhunter',
    description='Automatically find the streaming URL for a specific IP Camera'
)

parser.add_argument('--ip',  required=True, type=str, help='The IP Camera address')

group = parser.add_mutually_exclusive_group(required=True)

group.add_argument('--default-credentials', nargs='?', default=argparse.SUPPRESS, help='Tries to authenticate using a list of commonm default credentials')

group.add_argument('--user', type=str, help='The user to use to authenticate')

parser.add_argument('--pass', type=str, help='The password to use to authenticate', required= '--user' in sys.argv)

print(terminalColors.BOLD + terminalColors.OKBLUE + """
      ___________
     |           |___     ____  _                              _   _             _            
     |           |___|   / ___|| |_ _ __ ___  __ _ _ __ ___   | | | |_   _ _ __ | |_ ___ _ __ 
     |___________|       \___ \| __| '__/ _ \/ _` | '_ ` _ \  | |_| | | | | '_ \| __/ _ \ '__|
         |   |            ___) | |_| | |  __/ (_| | | | | | | |  _  | |_| | | | | ||  __/ | 
    |____|   |           |____/ \__|_|  \___|\__,_|_| |_| |_| |_| |_|\__,_|_| |_|\__\___|_|  
    |________/
    |
""" + terminalColors.ENDC)                                                                 

args = parser.parse_args()

try:
    if (ipaddress.ip_address(args.ip).version != 4):
        raise Exception("Ip must be an IPv4")
except:
    sys.exit("Error:\nInvalid IP: {}".format(args.ip))

print('Gathering clues about {}...'.format(args.ip))

try:
    hostname = socket.gethostbyaddr(args.ip)[0]

    printSuccess('Obtained hostname ({})'.format(hostname))
except:
    printError('Failed to obtain hostname')

mac = obtainMac(args.ip)

if (mac is not None):
    macInfo = requests.get('https://api.maclookup.app/v2/macs/' + mac).json()
    printSuccess('Obtained mac address info (Address: {}, Company: {})'.format(mac, macInfo['company']))
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

spinner = Halo(text='Fetching connection strings database...', spinner='dots')
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

cameraMakes = [ (e.text, e.attrs['href']) for e in modelsSoup.body.find('table').find_all('a') ]

printSuccess('Fetched camera connection strings database...')

name, url = cameraMakes[0]

urlsPage =  requests.get('https://www.ispyconnect.com/' + url, headers = normalHeaders)

urlsSoup = BeautifulSoup(urlsPage.text, features='lxml')

cameraUrlsRaw = [ e.find_all('td') for e in urlsSoup.body.find('table').find_all('tr') ]

cameraUrls = []

for e in cameraUrlsRaw:
    if len(e) == 4:
        cameraUrls.append((e[0].text.split(', '), e[1].text, e[2].text, e[3].text))

print(cameraUrls)
