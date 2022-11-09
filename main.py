import vt
import sys
import argparse
import base64
import os
import shodan
import json


def getShodanResults(query:str, client):
    #with open("results.json") as f:
    #    results = json.loads(f.read())
    #print(results.keys())

    results = client.search('clemson')
    matches = []
    for match in results["matches"]:
        matches.append({
            "ip":match["ip_str"],
            "port":match["port"]
        })
    return matches

def scanURL(url:str, vtClient, shodanClient):

    url_id = vt.url_id("http://www.virustotal.com")
    res = vtClient.get_object("/urls/{}", url_id)


    #res = {'harmless': 0, 'malicious': 0, 'suspicious': 0, 'undetected': 90, 'timeout': 0}
    res["matches"] = getShodanResults(url, shodanClient)
    res["value"] = url
    
    return res

def scanFile(filename:str, client):
    if not os.path.exists(filename):
        return None

    #res = {'harmless': 0, 'malicious': 0, 'suspicious': 0, 'undetected': 90, 'timeout': 0}
    #res["value"] = filename
    #return res

    with open(filename, "rb") as f:
        analysis = client.scan_file(f, wait_for_completion=True)
    res = analysis.stats
    res["value"] = filename
    return res

def handleReadFile(filename:str, vtClient, shodanClient):
    with open(filename, "r") as f:
        contents = [x[:-1] for x in f.readlines() if x.strip() != ""]
    
    for x in contents:
        if os.path.exists(x):
            res = scanFile(x, vtClient)
        else:
            res = scanURL(x.strip(), vtClient, shodanClient)
        print(res)

def handleUrl(url:str, vtClient, shodanClient):
    res = scanURL(url, vtClient, shodanClient)
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
    parser.add_argument("-s", "--shodan", required=False)

    args = parser.parse_args()

    if not (args.readfile or args.url or args.file or args.shodan):
        print("Please enter something.")
        return
    if args.readfile and args.url:
        print("Please specify either a file or a URL, not both.")
        return
    
    with open("key", "r") as f:
        vtKey = f.readline()
        shodanKey = f.readline()
    
    vtclient = vt.Client(vtKey)
    shodanclient = shodan.Shodan(shodanKey)

    if args.readfile:
        handleReadFile(args.readfile, vtclient, shodanclient)
    elif args.url:
        handleUrl(args.url, vtclient, shodanclient)
    elif args.file:
        handleFile(args.file, vtclient)

if __name__ == "__main__":
    main()