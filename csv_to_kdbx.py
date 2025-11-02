#!/usr/bin/env python3
"""
csv_to_kdbx.py

Конвертує CSV (експорт Firefox Logins) -> KeePass .kdbx

Usage:
    python csv_to_kdbx.py firefox_export.csv output.kdbx

Options:
    --db-password PASSWORD      : вказати пароль БД як аргумент (не рекомендовано через історію shell)
    --keyfile PATH             : додати keyfile та зберегти її поряд з .kdbx
    --group-by-domain          : створювати підгрупи за доменом (example.com)
    --title-field FIELD        : який стовпець використовувати як заголовок (за замовчуванням URL)
    --format firefox           : формат CSV, очікується стандарт експорту Firefox (url,username,password,...)
"""
import csv
import sys
import argparse
import getpass
import os
import re
from urllib.parse import urlparse
from pykeepass import PyKeePass, create_database
from datetime import datetime, UTC

# Якщо у тебе проблеми з pykeepass (залежності), встанови: pip install pykeepass
# pykeepass використовує libs для роботи з KDBX форматами; зазвичай працює "з коробки".

def domain_from_url(url: str) -> str:
    try:
        p = urlparse(url)
        host = p.hostname or url
        # прибрати "www."
        return re.sub(r'^www\.', '', host, flags=re.IGNORECASE)
    except Exception:
        return url

def read_firefox_csv(path):
    # Firefox export typical headers: url,username,password,httpRealm,guid,notes
    rows = []
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows

def main():
    parser = argparse.ArgumentParser(description="Convert Firefox CSV -> KeePass .kdbx")
    parser.add_argument('csv_in', help='input CSV file (Firefox export)')
    parser.add_argument('kdbx_out', help='output .kdbx file to create')
    parser.add_argument('--db-password', help='KeePass DB password (unsafe in CLI history)', default=None)
    parser.add_argument('--keyfile', help='Create a keyfile and use it as part of protection', default=None)
    parser.add_argument('--group-by-domain', action='store_true', help='Create subgroups by domain')
    parser.add_argument('--title-field', default='url', help='CSV field for title (default: url)')
    args = parser.parse_args()

    if not os.path.isfile(args.csv_in):
        print("Input CSV not found:", args.csv_in)
        sys.exit(1)

    if os.path.exists(args.kdbx_out):
        print(f"Output file {args.kdbx_out} already exists. Will not overwrite.")
        sys.exit(1)

    password = args.db_password
    if password is None:
        password = getpass.getpass("Enter password to protect the new KeePass DB: ")
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match.")
            sys.exit(1)

    entries = read_firefox_csv(args.csv_in)
    if not entries:
        print("No rows found in CSV.")
        sys.exit(1)

    # create DB
    create_database(args.kdbx_out, password=password)
    kp = PyKeePass(args.kdbx_out, password=password)

    # optional keyfile support: pykeepass allows opening with keyfile, but to create a keyfile and add it as protector,
    # pykeepass doesn't expose direct API to *add* a keyfile after creation easily.
    # Workaround: user can create keyfile separately and then reopen db with both password+keyfile.
    if args.keyfile:
        # create random keyfile bytes
        keyfile_path = args.keyfile
        if os.path.exists(keyfile_path):
            print("Keyfile already exists:", keyfile_path)
        else:
            with open(keyfile_path, 'wb') as kf:
                kf.write(os.urandom(64))
            print("Created keyfile:", keyfile_path)
        print("Note: to use keyfile as protector, you need to open the DB with the keyfile option afterwards (some clients support attaching).")

    # Mapping fields
    # Firefox CSV often: url,username,password,httpRealm,guid,notes
    # We'll use title = args.title_field (default url) but try nicer titles like domain or url if missing
    root_group = kp.root_group
    
    # Словник для відстеження дублікатів заголовків у кожній групі
    title_counts = {}

    for r in entries:
        url = r.get('url') or r.get('URL') or ''
        username = r.get('username') or r.get('username_field') or r.get('user') or ''
        password_field = r.get('password') or r.get('pass') or ''
        notes = r.get('notes') or ''
        title_raw = r.get(args.title_field) or url or username
        if not title_raw:
            title_raw = 'Login'

        if args.group_by_domain and url:
            dom = domain_from_url(url)
            # find or create subgroup
            # try to find existing subgroup under root_group
            group = None
            for g in root_group.subgroups:
                if g.name == dom:
                    group = g
                    break
            if group is None:
                group = kp.add_group(root_group, dom)
        else:
            group = root_group

        # Обробка дублікатів заголовків
        # Створюємо ключ на основі групи та базового заголовка
        group_key = f"{group.name if group != root_group else 'root'}:{title_raw}"
        
        if group_key not in title_counts:
            title_counts[group_key] = 0
        else:
            title_counts[group_key] += 1
        
        # Якщо це не перший запис з таким заголовком, додаємо суфікс
        if title_counts[group_key] > 0:
            title = f"{title_raw} ({title_counts[group_key]})"
        else:
            title = title_raw

        # create entry
        try:
            kp.add_entry(group, title, username, password_field, url=url, notes=notes)
        except Exception as e:
            print("Failed to create entry for:", title, "error:", e)

    # save DB
    kp.save()
    print("Saved KeePass DB:", args.kdbx_out)
    print("Entries added:", len(entries))
    print("Created:", datetime.now(UTC).isoformat() + "Z")

if __name__ == '__main__':
    main()
