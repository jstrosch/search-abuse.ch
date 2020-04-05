#!/usr/bin/env python

__author__ = "Josh Stroschein"
__version__ = "0.0.1"
__maintainer__ = "Josh Stroschein"

import sys, os, optparse, datetime, json, time, random, requests, zipfile
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#ignore TLS cert errors
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

http_download_timeout = 10 #in seconds

api_base_url = "https://urlhaus-api.abuse.ch/v1/"
user_agent = "Abuse.CH Research"
payloads_url = "payloads/recent/"
urls_url = "urls/recent/"
download_url = "overview/"
urls_tags = "tag/"

def setup_args():

    parser = optparse.OptionParser()

    parser.add_option('-q', '--query',
    action="store", dest="query",
    help="The type of search - payloads, urls", default="payloads")

    parser.add_option('-f', '--filetype',
    action="store", dest="filetype",
    help="File type to search for - exe, doc, unknown", default="doc") 

    parser.add_option('-d', '--directory',
    action="store", dest="directory",
    help="Location to save the downloaded samples", default="samples")

    parser.add_option('-l', '--limit',
    action="store", dest="limit",
    help="Limit number of results to download", default=200)

    parser.add_option('-s', '--shuffle',
    action="store", dest="shuffle",
    help="Shuffle the list of returned results before downloading - values are y or n", default="n")

    parser.add_option('-p','--proxies',
    action="store", dest="proxies",
    help="Proxy for HTTP requests for downloading malware. Note, this is not for the initial request to Abuse.CH. Format is protocol|server,protocol|server...", default="")

    parser.add_option('-v', '--verbose',
    action="store", dest="verbose",
    help="Print results of key aspects of the script, such as total results found, number downloaded, et cetera", default="n") 
    
    parser.add_option('-e', '--extract',
    action="store", dest="extract",
    help="Extract the downloaded samples from the zip - default downloads from Abuse.ch returns zipped files w/o password", default="n") 

    parser.add_option('-t', '--tag',
    action="store", dest="tag",
    help="Tag to filter URLs", default="")

    return parser.parse_args()

def download_sample(download_url, save_directory, save_name, save_extension, proxies):
    download = None
    
    try:
        download = requests.get(download_url, timeout = http_download_timeout, verify=False, proxies = proxies)

        if not os.path.exists(save_directory):
            os.makedirs(save_directory)

        with open(save_directory + "/" + save_name + save_extension, "wb") as file:
            file.write(download.content)
    except Exception as e:
        print("[!] Problem with " + download_url.replace("http","hxxp"))
        print(e)

def main(argv):

    options, args = setup_args() 
    parameters = {}
    proxies = {}
    headers = {
        "accept":"application/json",
        "Content-Type":"application/x-www-form-urlencoded",
        "User-Agent":user_agent
    }

    download_count = 0

    if options.query == "payloads":
        resp = requests.get(api_base_url + payloads_url, headers=headers)
        results = json.loads(resp.text)

        results = results["payloads"]

        if options.shuffle == "y":
            random.shuffle(results)

        for result in results:
            if result["file_type"] == options.filetype:
                print("[*] Downloading sample... " + result["md5_hash"])
                download_sample(result["urlhaus_download"],options.directory, result["sha256_hash"],".zip", proxies)

                download_count = download_count + 1

                if download_count >= int(options.limit):
                    print("[!] Download limit reached")
                    break

        if options.extract == "y":
            for f in os.listdir(options.directory):
                try:
                    with zipfile.ZipFile(os.path.join(options.directory,f)) as zip_ref:
                        zip_ref.extractall(options.directory)
                except:
                    print("[!] problem with this zip file :( - " + f)
                finally:
                    os.remove(os.path.join(options.directory,f))

    elif options.query == "urls":

            dl_urls = []

            resp = requests.get(api_base_url + urls_url, headers=headers)
            results = json.loads(resp.text)
        
            results = results["urls"]

            if options.shuffle == "y":
                random.shuffle(results)

            if options.proxies:
                for proxy in options.proxies.split(","):
                    key,value = proxy.split("|")
                    proxies[key] = value

            for result in results:
                if result["url_status"] == "online" and result["threat"] == "malware_download" and (not result["tags"] is None and (options.filetype in result["tags"] and not "zip" in result["tags"])) and not result["url"] in dl_urls:
                    print("[*] Downloading sample from... " + result["url"].replace("http","hxxp"))

                    ext = ".bin"
                    if "zip" in result["tags"]:
                        ext = ".zip"
                    download_sample(result["url"],options.directory, result["id"],ext, proxies)

                    dl_urls.append(result["url"])

                    download_count = download_count + 1
                    
                    if download_count >= int(options.limit):
                        print("[!] Download limit reached")
                        break  

    elif options.query == "opendirs-recent":
        opendir_count = 0
        resp = requests.get(api_base_url + urls_url, headers=headers)
        results = json.loads(resp.text)
        results = results["urls"]

        if options.shuffle == "y":
            random.shuffle(results)

        print("[*] Received " + str(len(results)) + " results")

        for result in results:
            
            if result["url_status"] in ["online","unknown","offline"] and result["tags"] and "opendir" in result["tags"]:
                url = result["url"]
                print("[" + result["date_added"] + "] opendir " + result["url_status"] + " at... " + url.replace("http","hxxp") + " (" + result["threat"] +")")

                opendir_count = opendir_count + 1

                if opendir_count >= int(options.limit):
                    print("[!] OpenDir limit reached")
                    break

    elif options.query == "tag":

        result_cnt = 0

        if not options.tag is "":
            post_data = {'tag':options.tag}
            resp = requests.post(api_base_url + urls_tags, data = post_data, headers=headers)

            results = json.loads(resp.text)
            results = results["urls"]

            if options.shuffle == "y":
                random.shuffle(results)

            print("[*] Received " + str(len(results)) + " results")

            for result in results:
                
                if result["url_status"] in ["online","unknown"]:
                    url = result["url"]
                    print("[" + result["dateadded"] + "] " + options.tag + " " + result["url_status"] + " at... " + url.replace("http","hxxp") + " (" + result["threat"] +")")

                    result_cnt = result_cnt + 1

                    if result_cnt >= int(options.limit):
                        print("[!] OpenDir limit reached")
                        break

    if options.verbose == "y":
        print("[*] Downloaded " + str(download_count) + " samples")

if __name__ == '__main__':
	main(sys.argv[1:])