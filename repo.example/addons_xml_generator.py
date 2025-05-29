# -*- coding: utf-8 -*-
import os
import hashlib

# Nastav cestu ku koreňu repozitára (tu kde sú zložky doplnkov)
addons_path = os.path.dirname(os.path.abspath(__file__))

# Výsledné súbory
addons_xml = ''
addons_xml_path = os.path.join(addons_path, "addons.xml")
addons_xml_md5_path = os.path.join(addons_path, "addons.xml.md5")

# Generovanie zoznamu doplnkov
def generate_addons_xml():
    global addons_xml
    addons_xml = u"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<addons>\n"
    for folder in sorted(os.listdir(addons_path)):
        folder_path = os.path.join(addons_path, folder)
        addon_xml = os.path.join(folder_path, "addon.xml")
        if os.path.isdir(folder_path) and os.path.isfile(addon_xml):
            with open(addon_xml, "r", encoding="utf-8") as f:
                content = f.read()
                content = content.strip()  # Remove leading/trailing whitespace
                addons_xml += content + u"\n"
    addons_xml += u"</addons>\n"

    # Zapíš addons.xml
    with open(addons_xml_path, "w", encoding="utf-8") as f:
        f.write(addons_xml)

    # Zapíš addons.xml.md5
    md5_hash = hashlib.md5(addons_xml.encode('utf-8')).hexdigest()
    with open(addons_xml_md5_path, "w") as f:
        f.write(md5_hash)

if __name__ == "__main__":
    generate_addons_xml()
    print("addons.xml a addons.xml.md5 boli vygenerované!")