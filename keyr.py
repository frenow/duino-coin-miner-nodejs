# This Python file uses the following encoding: utf-8
# My Version of Random KEYS.LOL made my Mizogg https://mizogg.co.uk
from bit import *
from bit.format import bytes_to_wif
import random, codecs, sys, atexit, time, requests, os
from rich.console import Console

console = Console()
console.clear()
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple

my_colours = [W, R, G, O, B, P]
icons = ['⏳', 'ℹ️', '✅', '⛔️', '🔁', '🔑', '💸', '😔', '🌍', '✍️', '🚌', '👇', '📋', '📣', '🤩', '😀', '😃', '😄', '😁',
         '😆', '😅', '😂', '🤣', '🥲', '☺️', '😊', '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘', '😗', '😙', '😚',
         '😋', '😛', '😝', '😜', '🤪', '🤨', '🧐', '🤓', '😎', '🥸', '🤩', '🥳', '😏', '😒', '😞', '😔', '😟', '😕',
         '🙁', '☹️', '😣', '😖', '😫', '😩', '🥺', '😢', '😭', '😤', '😠', '😡', '🤬', '🤯', '😳', '🥵', '🥶', '😱',
         '😨', '😰', '😥', '😓', '🤗', '🤔', '🤭', '🤫', '🤥', '😶', '😐', '😑', '😬', '🙄', '😯', '😦', '😧', '😮',
         '😲', '🥱', '😴', '🤤', '😪', '😵', '🤐', '🥴', '🤢', '🤮', '🤧', '😷', '🤒', '🤕', '🤑', '🤠', '😈', '👿',
         '👹', '👺', '🤡', '💩', '👻', '💀', '☠️', '👽', '👾', '🤖', '🎃', '😺', '😸', '😹', '😻', '😼', '😽', '🙀',
         '😿', '😾', '👋', '🤚', '🖐', '✋', '🖖', '👌', '🤌', '🤏', '✌️', '🤞', '🤟', '🤘', '🤙', '👈', '👉', '👆',
         '🖕', '👇', '☝️', '👍', '👎', '✊', '👊', '🤛', '🤜', '👏', '🙌', '👐', '🤲', '🤝', '🙏', '✍️', '💅', '🤳',
         '💪', '🦾', '🦵', '🦿', '🦶', '👣', '👂', '🦻', '👃', '🫀', '🫁', '🧠', '🦷', '🦴', '👀', '👁', '👅', '👄',
         '💋', '🩸', '🐒', '🐔', '🐧', '🐦', '🐤', '🐣', '🐥', '🦆', '🦅', '🦉', '🦇', '🐺', '🐗', '🐴', '🦄', '🐝',
         '🪱', '🐛', '🦋', '🐌', '🐞', '🐜', '🪰', '🪲', '🪳', '🦟', '🦗', '🕷', '🕸', '🦂', '🐢', '🐍', '🦎', '🦖',
         '🦕', '🐙', '🦑', '🦐', '🦞', '🦀', '🐡', '🐠', '🐟', '🐬', '🐳', '🐋', '🦈', '🐊', '🐅', '🐆', '🦓', '🦍',
         '🦧', '🦣', '🐘', '🦛', '🦏', '🐪', '🐫', '🦒', '🦘', '🦬', '🐃', '🐂', '🐄', '🐎', '🐖', '🐏', '🐑', '🦙',
         '🐐', '🦌', '🐕', '🐩', '🦮', '🐕‍🦺', '🐈', '🐈‍⬛', '🪶', '🐓', '🦃', '🦤', '🦚', '🦜', '🦢', '🦩', '🕊',
         '🐇', '🦝', '🦨', '🦡', '🦫', '🦦', '🦥', '🐁', '🐀', '🐿', '🦔', '🐾', '🐉', '🐲', '🌵', '🎄', '🌲', '🌳',
         '🌴', '🪵', '🌱', '🌿', '☘️', '🍀', '🎍', '🪴', '🎋', '🍃', '🍂', '🍁', '🍄', '🐚', '🪨', '🌾', '💐', '🌷',
         '🌹', '🥀', '🌺', '🌸', '🌼', '🌻', '🌞', '🌝', '🌛', '🌜', '🌚', '🌕', '🌖', '🌗', '🌘', '🌑', '🌒', '🌓',
         '🌔', '🌙', '🌎', '🌍', '🌏', '🪐', '💫', '⭐️', '🌟', '✨', '⚡️', '☄️', '💥', '🔥', '🌪', '🌈', '☀️', '🌤',
         '⛅️', '🌥', '☁️', '🌦', '🌧', '⛈', '🌩', '🌨', '❄️', '☃️', '⛄️', '🌬', '💨', '💧', '💦', '☔️', '☂️', '🌊',
         '🌫', '⏰', '💰', '🎅🏻', '🎄', '🎁', '🎶']

animation = ["□□□□□□□□□□□□□□□□□□□□  0%", "■□□□□□□□□□□□□□□□□□□□  5%", "■■□□□□□□□□□□□□□□□□□□ 10%",
             "■■■□□□□□□□□□□□□□□□□□ 15%", "■■■■□□□□□□□□□□□□□□□□ 20%", "■■■■■□□□□□□□□□□□□□□□ 25%",
             "■■■■■■□□□□□□□□□□□□□□ 30%", "■■■■■■■□□□□□□□□□□□□□ 35%", "■■■■■■■■□□□□□□□□□□□□ 40%",
             "■■■■■■■■■□□□□□□□□□□□ 45%", "■■■■■■■■■■□□□□□□□□□□ 50%", "■■■■■■■■■■■□□□□□□□□□ 55%",
             "■■■■■■■■■■■■□□□□□□□□ 60%", "■■■■■■■■■■■■■□□□□□□□ 65%", "■■■■■■■■■■■■■■□□□□□□ 70%",
             "■■■■■■■■■■■■■■■□□□□□ 75%", "■■■■■■■■■■■■■■■■□□□□ 80%", "■■■■■■■■■■■■■■■■■□□□ 85%",
             "■■■■■■■■■■■■■■■■■■□□ 90%", "■■■■■■■■■■■■■■■■■■■□ 95%", "■■■■■■■■■■■■■■■■■■■■100%"]

# animation = ["□□□□□□□□□□□□□□□□□□□□  0%","🔑□□□□□□□□□□□□□□□□□□□  5%","🔑🔑□□□□□□□□□□□□□□□□□□ 10%","🔑🔑🔑□□□□□□□□□□□□□□□□□ 15%","🔑🔑🔑🔑□□□□□□□□□□□□□□□□ 20%","🔑🔑🔑🔑🔑□□□□□□□□□□□□□□□ 25%","🔑🔑🔑🔑🔑🔑□□□□□□□□□□□□□□ 30%","🔑🔑🔑🔑🔑🔑🔑□□□□□□□□□□□□□ 35%","🔑🔑🔑🔑🔑🔑🔑🔑□□□□□□□□□□□□ 40%","🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□□□□□□□□ 45%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□□□□□□□ 50%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□□□□□□ 55%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□□□□□ 60%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□□□□ 65%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□□□ 70%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□□ 75%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□□ 80%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□□ 85%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□□ 90%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑□ 95%","🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑100%"]

console.print(" [yellow]-----------------KEYS.LOL----------------------[/yellow]")
console.print("[yellow]                 Starting search...[/yellow]")
console.print("[yellow]                Using Block Chain API...[/yellow]")
console.print(" [yellow]-----------------KEYS.LOL----------------------[/yellow]")
console.print("[yellow] ℹ️ Start search... Pick Range to start (Min=0 Max=256) ℹ️ [/yellow] ")
x=int(input(" ✅ Start range in BITs (Puzzle StartNumber) ✍️ -> "))
a = 2 **x
y=int(input(" ⛔️ Stop range Max in BITs (Puzzle StopNumber)✍️ -> "))
b = 2 **y
console.print("[purple]⏳Starting search... Please Wait ⏳[/purple]")
console.print("==========================================================")

def get_all_key(data):
    key = Key.from_int(data[-1])
    wifu = bytes_to_wif(key.to_bytes(), compressed=False)
    wifc = bytes_to_wif(key.to_bytes(), compressed=True)
    keyu = Key(wifu)
    caddr = key.address
    uaddr = keyu.address
    result = {
        'key': key,
        'wifu': wifu,
        'wifc': wifc,
        'keyu': keyu,
        'caddr': caddr,
        'uaddr': uaddr
    }
    return result


def main():
    counter = 0
    total = 0
    pagenumber = 0
    while True:
        lol = random.choice(icons)
        colour = random.choice(my_colours)
        ran = random.randrange(a, b)
        seed = str(ran)
        data_wallet = map(get_all_key, [(i, ran + i) for i in range(128)])
        wallets = [wallet_ for wallet_ in data_wallet]
        query = [i['caddr'] for i in wallets]
        query1 = [i['uaddr'] for i in wallets]
        counter += 1
        total += 256
        pagenumber = (int(seed) // 128) + 1
        if len(query) == 128 or len(query1) == 128:

            try:
                request = requests.get(
                    "https://blockchain.info/multiaddr?active=%s" % ','.join(query) + '&base=BCH&cors=true', timeout=10)
                request = request.json()

                def find_wallet():
                    print('💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰')
                    console.print('[bold green]📋 Page Number : [' + str(pagenumber) + '] [/bold green]')
                    print('Matching Key ==== Found!!!\n PrivateKey: ' + wallets[0]['key'].to_hex())
                    print(
                        '⛔️WARNING !!!!  Any Winners found will be Within 128 Private Key range of this Scan !!!! WARNING !!!!⛔️')
                    print('💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰🤩💸💰')
                    with open("winner.txt", "a") as f:
                        print("start write")
                        text = f"""\n=============Bitcoin Address with Balance Found=====================
                                \nPage Number: {str(pagenumber)}
                                \nPrivateKey (hex): {wallets[0]['key'].to_hex()}
                                \nBitcoin Address Compressed : {wallets[0]['caddr']}
                                \nBitcoin Address UnCompressed : {wallets[0]['uaddr']}
                                \nPrivateKey (wif) Compressed :  {wallets[0]['wifc']}
                                \nPrivateKey (wif) UnCompressed : {wallets[0]['wifu']}
                                \nCheck All Addresses within 128 in this range to find wallet\n"""
                        f.write(text)

                for row in request["addresses"]:
                    print(row)
                    if row["final_balance"] or row["total_received"] > 0:
                        find_wallet()
                        break
                request1 = requests.get("https://blockchain.info/multiaddr?active=%s" % ','.join(query1), timeout=10)
                request1 = request1.json()

                for row in request1["addresses"]:
                    print(row)
                    if row["final_balance"] or row["total_received"] > 0:
                        find_wallet()
                        break
            except:
                pass

            query = []
            console.print('[red] [' + str(counter) + '] ------------------------[/red]')
            console.print('[red]🔁 Total Checked 👇[' + str(total) + '] [/red]')
            print('😒😞😔😟😕 Bitcoin Address Compressed : ' + wallets[0]['caddr'])
            print('😒😞😔😟😕 Bitcoin Address UnCompressed : ' + wallets[0]['uaddr'])
            print('🔑 Private Key (HEX) : ' + wallets[0]['key'].to_hex())
            print('🔑 Private Key (DEC) : ' + seed)
            print('🔑 PrivateKey (wif) Compressed : ' + wallets[0]['wifc'])
            print('🔑 PrivateKey (wif) UnCompressed : ' + wallets[0]['wifu'])
            console.print('[red]📋 Page Number : [' + str(pagenumber) + '] [/red]')
            for i in range(len(animation)):
                time.sleep(0.5)
                sys.stdout.write("\r" + colour + lol + "Loading 10 Seconds :" + animation[i % len(animation)])
                sys.stdout.flush()


if __name__ == '__main__':
    while True:
        main()
