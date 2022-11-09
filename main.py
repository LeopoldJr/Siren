import vt
import sys
import argparse
import base64
import os
import 

# calls 
def scanURL(url:str, client):
    res = {'harmless': 0, 'malicious': 0, 'suspicious': 0, 'undetected': 90, 'timeout': 0}
    res["value"] = url
    return res

    url_id = vt.url_id(url)
    return client.get_object("/urls/{}", url_id).last_analysis_stats

def scanFile(filename:str, client):
    if not os.path.exists(filename):
        return None

    res = {'harmless': 0, 'malicious': 0, 'suspicious': 0, 'undetected': 90, 'timeout': 0}
    res["value"] = filename
    return res

    with open(filename, "rb") as f:
        analysis = client.scan_file(f, wait_for_completion=True)
    res = analysis.stats
    res["value"] = filename
    return res

def handleReadFile(filename:str, client):
    with open(filename, "r") as f:
        contents = [x[:-1] for x in f.readlines() if x.strip() != ""]
    
    for x in contents:
        if os.path.exists(x):
            res = scanFile(x, client)
        else:
            res = scanURL(x, client)
        print(res)

def handleUrl(url:str, client):
    res = scanURL(url, client)
    print(res)

def handleFile(filepath:str, client):
    res = scanFile(filepath, client)
    print(res)

def main():
    print("""
  _________.________________________ _______   
 /   _____/|   \\______   \\_   _____/ \\      \\  
 \\_____  \\ |   ||       _/|    __)_  /   |   \\ 
 /        \\|   ||    |   \\|        \\/    |    \\
/_______  /|___||____|_  /_______  /\\____|__  /
        \\/             \\/        \\/         \\/ 
    """)
    print("Your one-stop shop for all things infosec.\n\n")

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--readfile", required=False)
    parser.add_argument("-u", "--url", required=False)
    parser.add_argument("-f", "--file", required=False)

    args = parser.parse_args()

    if not (args.readfile or args.url or args.file):
        print("Please enter something.")
        return
    if args.readfile and args.url:
        print("Please specify either a file or a URL, not both.")
        return
    
    with open("key", "r") as f:
        vtKey = f.readline()
        shodanKey = f.readline

    client = vt.Client(vtKey)


    if args.readfile:
        handleReadFile(args.readfile, client)
    elif args.url:
        handleUrl(args.url, client)
    elif args.file:
        handleFile(args.file, client)

if __name__ == "__main__":
    main()