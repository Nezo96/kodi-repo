import sys
import xbmcplugin
import xbmcgui
import xbmcaddon
import requests  # teraz budeš mať requests cez závislosť

addon_handle = int(sys.argv[1])
xbmcplugin.setContent(addon_handle, 'videos')

def main_menu():
    url = sys.argv[0] + '?action=hello'
    li = xbmcgui.ListItem('Zobraziť Hello z requests')
    xbmcplugin.addDirectoryItem(addon_handle, url, li, False)
    xbmcplugin.endOfDirectory(addon_handle)

def say_hello():
    try:
        # Nové testovacie API, ktoré funguje vždy
        response = requests.get('https://jsonplaceholder.typicode.com/todos/1')
        data = response.json()
        # Zobrazíme iba title z JSONu
        xbmcgui.Dialog().ok('Výsledok requests', f"ID: {data['id']}\nTitle: {data['title']}\nCompleted: {data['completed']}")
    except Exception as e:
        xbmcgui.Dialog().notification('Chyba', str(e), xbmcgui.NOTIFICATION_ERROR)

if __name__ == '__main__':
    args = sys.argv[2][1:]
    if 'action=hello' in args:
        say_hello()
    else:
        main_menu()