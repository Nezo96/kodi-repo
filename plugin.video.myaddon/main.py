import sys
import xbmcplugin
import xbmcgui
import xbmcaddon
import requests  # teraz budeš mať requests cez závislosť
import xbmc
import traceback
import xml.etree.ElementTree as ET

import hashlib

from md5crypt_passlib import md5_crypt

addon_handle = int(sys.argv[1])
addon = xbmcaddon.Addon()
xbmcplugin.setContent(addon_handle, 'videos')

REALM = ':Webshare:'

def must_fill_settings():
    return not addon.getSetting('username') or not addon.getSetting('password') \
        or addon.getSetting('language') == '' or addon.getSetting('fallback_language') == '' or addon.getSetting('search_type') == ''

def main_menu():
    # Vyhľadať film
    url = sys.argv[0] + '?action=search_movie'
    li = xbmcgui.ListItem('Vyhľadať film')
    xbmcplugin.addDirectoryItem(addon_handle, url, li, False)

    # História hľadania
    url = sys.argv[0] + '?action=history'
    li = xbmcgui.ListItem('História hľadania')
    xbmcplugin.addDirectoryItem(addon_handle, url, li, False)

    # Test nastavení
    url = sys.argv[0] + '?action=test_settings'
    li = xbmcgui.ListItem('Test nastavení')
    xbmcplugin.addDirectoryItem(addon_handle, url, li, False)

    # Zmena nastavení
    url = sys.argv[0] + '?action=settings'
    li = xbmcgui.ListItem('Zmeniť nastavenia')
    xbmcplugin.addDirectoryItem(addon_handle, url, li, False)

    # Odhlásenie
    url = sys.argv[0] + '?action=logout'
    li = xbmcgui.ListItem('Odhlásiť sa')
    xbmcplugin.addDirectoryItem(addon_handle, url, li, False)

    xbmcplugin.endOfDirectory(addon_handle)

def search_movie():
    movie = xbmcgui.Dialog().input("Zadaj názov filmu")
    if movie:
        search_type = addon.getSetting('search_type')
        values = ["relevance", "najnovšie", "hodnotenie"]
        selected_value = values[int(search_type)]
        xbmcgui.Dialog().ok("Hľadáš film", f"Vyhľadáva sa: {movie} \nTyp vyhľadávania: {selected_value}")
        # xbmcgui.Dialog().ok("Nastavenia", f"Typ vyhľadávania: {selected_value}")
    xbmcplugin.endOfDirectory(addon_handle)

def history():
    xbmcgui.Dialog().ok("História", "Tu sa neskôr zobrazí história hľadaní.")
    xbmcplugin.endOfDirectory(addon_handle)

def test_settings():
    username = addon.getSetting('username')
    password = addon.getSetting('password')
    language = addon.getSetting('language')
    fallback_language = addon.getSetting('fallback_language')

    languages = ["Slovensky", "Česky", "English", "Deutsch"]

    xbmcgui.Dialog().ok(
        "Tvoje nastavenia",
        f"Meno: {username}\nHeslo: {'*' * len(password)}\n"
        f"Preferovaný jazyk: {languages[int(language)]}\n"
        f"Záložný jazyk: {languages[int(fallback_language)]}"
    )

def get_salt(user_name):
    url = "https://webshare.cz/api/salt/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    data = {
        "username_or_email": user_name
    }
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        xbmc.log(f"[Webshare] get_salt odpoveď: {response.text}", xbmc.LOGINFO)
        root = ET.fromstring(response.content)
        salt = root.findtext("salt")
        if not salt:
            err = root.findtext("message")
            xbmc.log(f"[Webshare] get_salt ERROR: {err}", xbmc.LOGERROR)
            xbmcgui.Dialog().ok("Chyba", f"Chyba získavania salt: {err}")
            return None
        xbmc.log(f"[Webshare] salt: {salt}", xbmc.LOGINFO)
        return salt
    except Exception as e:
        xbmc.log(f"[Webshare] Exception get_salt: {e}", xbmc.LOGERROR)
        xbmcgui.Dialog().ok("Chyba", f"Výnimka pri získavaní salt: {e}")
        return None

def hash_password(user_name, password, salt):
    md5_pass = md5_crypt(password, salt)
    print(f"[DEBUG] md5_crypt: {md5_pass}")
    password_sha1 = hashlib.sha1(md5_pass.encode('utf-8')).hexdigest()
    print(f"[DEBUG] password (SHA1(md5_crypt)): {password_sha1}")
    digest_str = f"{user_name}:Webshare:{password_sha1}"
    print(f"[DEBUG] Digest str: {digest_str}")
    digest = hashlib.md5(digest_str.encode('utf-8')).hexdigest()
    print(f"[DEBUG] digest: {digest}")
    return password_sha1, digest

def webshare_login(user_name, password):
    salt = get_salt(user_name)
    if not salt:
        return None
    password_hash, digest = hash_password(user_name, password, salt)
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
    url = "https://webshare.cz/api/login/"
    data = {
        'username_or_email': user_name,
        'password': password_hash,
        'digest': digest,
        'keep_logged_in': 1
    }
    try:
        response = requests.post(url, data=data, headers=headers, timeout=10)
        response.raise_for_status()
        xbmc.log(f"[Webshare] login odpoveď: {response.text}", xbmc.LOGINFO)
        root = ET.fromstring(response.content)
        status = root.findtext('status')
        if status != "OK":
            message = root.findtext('message')
            code = root.findtext('code')
            xbmc.log(f"[Webshare] LOGIN ERROR: status={status}, code={code}, msg={message}", xbmc.LOGERROR)
            xbmcgui.Dialog().ok("Chyba pri prihlásení", "Nepodarilo sa prihlásiť so zadnými údajmi, prosím skontrolujte správnosť údajov meno a heslo")
            return None
        token = root.findtext('token')
        xbmc.log(f"[Webshare] LOGIN OK, token: {token}", xbmc.LOGINFO)
        addon.setSetting('login_token', token)
        if token:
            addon.setSetting('login_token', token)
            xbmcgui.Dialog().notification("Webshare", "Úspešne prihlásený", "", 3000)
            return token
        return token
    except Exception as e:
        xbmc.log(f"[Webshare] Exception login: {e}", xbmc.LOGERROR)
        xbmcgui.Dialog().ok("Chyba", f"Výnimka pri prihlasovaní: {e}")
        return None

def check_login():
    user_name = addon.getSetting('username')
    password = addon.getSetting('password')
    if user_name and password:
        result = webshare_login(user_name, password)
        if not result:
             # login sa nepodaril, neskáč do main_menu!
            xbmcplugin.endOfDirectory(addon_handle)
            sys.exit()
    else:
        xbmcgui.Dialog().ok("Chýba nastavenie", "Vyplň meno a heslo v nastaveniach doplnku.")
        xbmcplugin.endOfDirectory(addon_handle)
        sys.exit()

if __name__ == '__main__':
    try:
        # Ak treba nastavenia, otvor ich, ukonči plugin
        if must_fill_settings():
            addon.openSettings()
            xbmcgui.Dialog().ok(
                "Nastavenia boli uložené",
                "Nastavenia boli uložené. Prosím, spustite doplnok znova."
            )
            xbmcplugin.endOfDirectory(addon_handle)
            sys.exit()

        args = sys.argv[2][1:]

        # Spracuj najprv odhlásenie (nemusí kontrolovať login/token)
        if 'action=logout' in args:
            addon.setSetting('login_token', "")
            addon.setSetting('username', "")
            addon.setSetting('password', "")
            addon.setSetting('language', "")
            addon.setSetting('fallback_language', "")
            xbmcgui.Dialog().notification("Webshare", "Odhlásený.", "", 4000)
            xbmcgui.Dialog().ok("Odhlásený", "Stlačte späť pre návrat do menu a doplnok znovu spustite.")
            xbmcplugin.endOfDirectory(addon_handle)
            sys.exit()

        # Ak treba login, urob login – ak neuspeje, plugin končí
        token = addon.getSetting('login_token')
        if not token:
            check_login()
            # --- ak si tu, máš login alebo token ---

        # Menu voľby
        if 'action=test_settings' in args:
            test_settings()
        elif 'action=search_movie' in args:
            search_movie()
        elif 'action=settings' in args:
            # Uložiť hodnoty pred otvorením settings
            old_username = addon.getSetting('username')
            old_password = addon.getSetting('password')
            old_language = addon.getSetting('language')
            old_fallback_language = addon.getSetting('fallback_language')
            old_search_type = addon.getSetting('search_type')

            # Otvôriť nastavenia
            addon.openSettings()

            # Po návrate zo settings načítať hodnoty znova
            new_username = addon.getSetting('username')
            new_password = addon.getSetting('password')
            new_language = addon.getSetting('language')
            new_fallback_language = addon.getSetting('fallback_language')
            new_search_type = addon.getSetting('search_type')

            # Ak sa niečo zásadné zmenilo, vymazať token
            if (old_username != new_username or
                old_password != new_password or
                old_language != new_language or
                old_fallback_language != new_fallback_language or
                old_search_type != new_search_type):
                addon.setSetting('login_token', "")
                xbmcgui.Dialog().ok(
                    "Nastavenia",
                    "Nastavenia boli zmenené. Pre uplatnenie zmien reštartujte doplnok."
                )
            else:
                xbmcgui.Dialog().ok(
                    "Nastavenia",
                    "Nastavenia neboli zmenené."
                )

            xbmcplugin.endOfDirectory(addon_handle)
            sys.exit()
        else:
            main_menu()
    except Exception as e:
        xbmc.log(f"[MYPLUGIN] Chyba v hlavnom bloku: {e}\n{traceback.format_exc()}", xbmc.LOGERROR)
        xbmcgui.Dialog().ok("Chyba", str(e))
        xbmcplugin.endOfDirectory(addon_handle)
        sys.exit()