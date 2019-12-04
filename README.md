# Abuse.CH URLHaus API - Search and Download
This is a small Python3 script that allows you to search and download samples from the URLHaus (by Abuse.ch) API. Functionality is based off of documentation for the API at [https://urlhaus-api.abuse.ch/](https://urlhaus-api.abuse.ch/). In it's current form, this script implements ["query recent URLs"](https://urlhaus-api.abuse.ch/#urls-recent) and ["query recent payloads"](https://urlhaus-api.abuse.ch/#urls-recent) functionality. 

_Please note, this script is designed to download the malicious samples directly from the recent URLs returned from URLHaus._

## Getting Started

This script requires Python3 and help is built in via the -h argument. No API keys are needed from Abuse.CH, but please be respectful of the free service they are providing.

## Finding Malicious Samples

This script generally works in two phases - the first is to request either recent URLs or recent payloads from URLHaus. The response is returned via JSON. For recent payloads, the JSON response is parsed and filtered and the samples downloaded directly from URLHaus as a ZIP archive (not password protected). For recent URLs, the JSON respons is parsed and filtered and it then attempts to download directly from the submitted URLs.

Changing filters is fairly straight-forward, check the conditionals that parse the JSON from the initial request. This JSON can also be printed to inspect the returned values, as the fields are defined in the API documentation. URLs are filtered as follows:

* url_status = online
* threat = malware_download
* tags include exe and not ZIP - I've encountered password protected ZIPs and dont' want to hassle with cracking

While downloading via URL the script maintains a list of unique URLs to avoid redundancy. However, this is not persisted across script executions.

Payload filters are currently only for file type.

## Downloading Malware

Once samples have been identified for download, the script will download them directly. The script allows for a proxy to be defined via the Requests module and the -p argument. However, this functionaly has not been fully tested and should be verified before use.

## Future Work

Right now this is a minimal implementation that focused on my immediate need to obtain malware samples, my intention is to continue to expand upon it's capability. Of course, pull requests/etc are all welcome :)