from suds.client import Client
from suds.wsse import Security, UsernameToken
import argparse
import logging
import urllib.request
import ssl
import suds.transport.http
import json
import requests
import sys
import hashlib
from timeit import default_timer as timer

__author__ = "Jouni Lehto"
__versionro__="0.0.3"

#Global variables
args = None
defectServiceClient = None
CHUNK_SIZE=100 #Max limit is 100 for getting mergedDefectIdDataObjs

class UnverifiedHttpsTransport(suds.transport.http.HttpTransport):
    def __init__(self, *args, **kwargs):
        super(UnverifiedHttpsTransport, self).__init__(*args, **kwargs)

    def u2handlers(self):
        handlers = super(UnverifiedHttpsTransport, self).u2handlers()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
        return handlers

class WebServiceClient:
    def __init__(self, webservice_type, url, username, password):
        if webservice_type == 'defectservice':
            self.wsdlFile = url + '/ws/v9/defectservice?wsdl'
        else:
            raise "unknown web service type: " + webservice_type
        self.client = Client(self.wsdlFile, transport=UnverifiedHttpsTransport())
        self.client.options.location = url + '/ws/v9/defectservice'
        self.security = Security()
        self.token =  UsernameToken(username, password)
        self.security.tokens.append(self.token)
        self.client.set_options(wsse=self.security)

class DefectserviceClient(WebServiceClient):
    def __init__(self,url, username, password):
        WebServiceClient.__init__(self,'defectservice', url, username, password)

def getSarifJsonHeader():
    return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

def getResults(stream, project):
    issues = getMergedDefectsForSnapshotScope(stream_name=stream, project_name=project)
    if issues:
        ruleIds, rules, sarifIssues = [],[],[]
        results = {}
        for issue in issues:
            locations = []
            ruleId = issue["checkerName"]
            sarifIssue = {"ruleId":ruleId}
            messageText, remediationText = f'[See in Coverity]({args.url}/query/defects.htm?project={project}&cid={str(issue["cid"])})\n', ""
            if not ruleId in ruleIds:
                rule = {"id": ruleId, "name": issue["type.name"], "shortDescription":{"text": issue["type.name"]}, 
                        "fullDescription":{"text":f'{issue["longDescription"][:1000] if issue["longDescription"] else "N/A"}', "markdown":f'{issue["longDescription"][:1000] if issue["longDescription"] else "N/A"}'},
                        "help":{"text":f'{issue["longDescription"] if issue["longDescription"] else "N/A"}', "markdown":getRuleHelpMarkdownMessage(issue)},
                        "properties": {"security-severity": nativeSeverityToNumber(issue['impact.displayName']), "tags": addTags(issue['issueKinds'], issue['cwe'])},
                        "defaultConfiguration":{"level":nativeSeverityToLevel(issue['impact.displayName'].lower())}}
                rules.append(rule)
                ruleIds.append(ruleId)
            for event in sorted(issue['events'], key=lambda x: x['eventNumber']):
                if not event['eventKind'] == "REMEDIATION":
                    lineNumber=f'{int(event["lineNumber"]) if event["lineNumber"] else 1}' 
                    locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri": event["filePathname"][1::]},"region":{"startLine":int(lineNumber)}}, 
                        "message" : {"text": f'Event Set {event["eventNumber"]}: {event["eventTag"]}: {event["eventDescription"]}'}}})
                    if "sub-events" in event and len(event['sub-events']) > 0:
                        for subevent in sorted(event['sub-events'], key=lambda x: x['eventNumber']):
                            sublineNumber=f'{int(subevent["lineNumber"]) if subevent["lineNumber"] else 1}'
                            locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri": subevent["filePathname"][1::]},"region":{"startLine": int(sublineNumber)}}, 
                                "message" : {"text": f'Event #{event["eventNumber"]}.{subevent["eventNumber"]}: {subevent["eventTag"]}: {subevent["eventDescription"]}'}}})
                if event["main"]:
                    mainlineNumber=f'{int(event["lineNumber"]) if event["lineNumber"] else 1}'
                    sarifIssue['locations'] = [{"physicalLocation":{"artifactLocation":{"uri":event["filePathname"][1::]},"region":{"startLine": int(mainlineNumber)}}}]
                    sarifIssue['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{issue["cid"]}{event["filePathname"][1::]}{mainlineNumber}').encode(encoding='UTF-8')).hexdigest()}
                    messageText += event['eventDescription']
            sarifIssue['message'] = {"text": messageText[:1000]}
            codeFlowsTable, loctionsFlowsTable = [], []
            threadFlows, loctionsFlows = {}, {}
            loctionsFlows['locations'] = locations
            loctionsFlowsTable.append(loctionsFlows)
            threadFlows['threadFlows'] = loctionsFlowsTable
            codeFlowsTable.append(threadFlows)
            sarifIssue['codeFlows'] = codeFlowsTable
            sarifIssues.append(sarifIssue)
        results["results"] = sarifIssues
        return results, rules
    else:
        logging.info(f'No issues found!')
        return {},[]

def getRuleHelpMarkdownMessage(issue):
    messageText = ""
    remediationText = ""
    messageText += f'{issue["longDescription"] if issue["longDescription"] else "N/A"}'
    if "local_effect" in issue and issue['local_effect']: messageText += f"\n\n## Local effect\n{issue['localEffect']}"
    for event in issue['events']:
        if event['eventKind'] == "REMEDIATION" and event['eventDescription']: messageText += f'\n\n## Remediation\n{event["eventDescription"]}\n\n'
    if issue['cwe']:
        messageText += f"\n\n## References\n* Common Weakness Enumeration: [CWE-{issue['cwe']}](https://cwe.mitre.org/data/definitions/{issue['cwe']}.html)"
    return messageText


def addTags(kinds, cwe):
    tags = []
    tags.extend(kinds)
    if cwe:
        tags.append(f'external/cwe/cwe-{cwe}')
    return tags

def getSarifJsonFooter(toolDriverName, rules):
    return {"driver":{"name":toolDriverName,"informationUri": f'{args.url if args.url else ""}',"version":__versionro__,"organization":"Synopsys","rules":rules}}

def nativeSeverityToLevel(argument): 
    switcher = { 
        "audit": "warning", 
        "high": "error", 
        "low": "note", 
        "medium": "warning"
    }
    return switcher.get(argument, "warning")

# Changing the native severity into sarif security-severity format
def nativeSeverityToNumber(argument): 
    switcher = { 
        "blocker": "9.8", 
        "critical": "9.1", 
        "high": "8.9", 
        "medium": "6.8",
        "audit": "6.8", 
        "low": "3.8",
        "info": "1.0",
        "unspecified": "0.0",
    }
    return switcher.get(argument, "6.8")

def getMergedDefectsForSnapshotScope(stream_name, project_name):
    projectIdDataObj=defectServiceClient.factory.create('projectIdDataObj')
    projectIdDataObj.name=project_name
    snapshotScopeDefectFilterSpecDataObj=defectServiceClient.factory.create('snapshotScopeDefectFilterSpecDataObj')
    streamIdDataObjs = []
    streamIdDataObj = defectServiceClient.factory.create('streamIdDataObj')
    streamIdDataObj.name=stream_name
    streamIdDataObjs.append(streamIdDataObj)
    snapshotScopeDefectFilterSpecDataObj.streamIncludeNameList=streamIdDataObjs
    impactNames = [impactName.strip().capitalize() for impactName in args.impactNameList.split(",")]
    logging.debug(f'Getting defects with impact names: {impactNames}')
    statusNames = [statusName.strip().capitalize() for statusName in args.statusNamesList.split(",")]
    logging.debug(f'Getting defects with statuses: {statusNames}')
    snapshotScopeDefectFilterSpecDataObj.impactNameList=impactNames
    snapshotScopeDefectFilterSpecDataObj.statusNameList=statusNames
    pageSpecDataObj=defectServiceClient.factory.create('pageSpecDataObj')
    pageSpecDataObj.pageSize=5000
    snapshotScopeSpecDataObj=defectServiceClient.factory.create('snapshotScopeSpecDataObj')
    snapshotScopeSpecDataObj.showSelector="last()"
    try:
        mergedDefectsPageDataObj = defectServiceClient.service.getMergedDefectsForSnapshotScope(projectId=projectIdDataObj,filterSpec=snapshotScopeDefectFilterSpecDataObj,pageSpec=pageSpecDataObj,snapshotScope=snapshotScopeSpecDataObj)
        if mergedDefectsPageDataObj and mergedDefectsPageDataObj.totalNumberOfRecords > 0:
            return getStreamDefects(mergedDefectsPageDataObj.mergedDefectIds, stream_name)
    except suds.WebFault as e:
        logging.error(e)

def getStreamDefects(mergedDefectIdDataObjs, stream_name):
    streamDefectFilterSpecDataObj = defectServiceClient.factory.create('streamDefectFilterSpecDataObj')
    streamIdDataObjs = []
    streamIdDataObj = defectServiceClient.factory.create('streamIdDataObj')
    streamIdDataObj.name = stream_name
    streamIdDataObjs.append(streamIdDataObj)
    streamDefectFilterSpecDataObj.streamIdList = streamIdDataObjs
    streamDefectFilterSpecDataObj.includeDefectInstances=True
    try:
        chunks = [mergedDefectIdDataObjs[i:i + CHUNK_SIZE] for i in range(0, len(mergedDefectIdDataObjs), CHUNK_SIZE)]
        streamDefectDataObjs = []
        collected_cids = 0
        logging.debug(f'Getting defects for {len(mergedDefectIdDataObjs)} cids in {CHUNK_SIZE} chunks...')
        for chunk in chunks:
            streamDefectDataObjs.append(defectServiceClient.service.getStreamDefects(mergedDefectIdDataObjs=chunk, filterSpec=streamDefectFilterSpecDataObj))
            collected_cids += len(chunk)
            logging.debug(f'Got defects for: {collected_cids}/{len(mergedDefectIdDataObjs)} CIDs')
        return parseDefects(streamDefectDataObjs)
    except suds.WebFault as e:
        logging.error(e)

def parseDefects(streamDefectDataObjs):
    issues = []
    if streamDefectDataObjs:
        for streamDefectDataObj in streamDefectDataObjs:
            for streamdefect in streamDefectDataObj:
                for defectInstance in streamdefect.defectInstances:
                    issue = {}
                    issue["cid"] = streamdefect.cid
                    issue["checkerName"] = defectInstance.checkerName
                    issue["longDescription"] = defectInstance.longDescription
                    issue["localEffect"] = defectInstance.localEffect
                    issue["cwe"] = f'{defectInstance.cwe if "cwe" in defectInstance else ""}'
                    issue["type.name"] = f'{defectInstance.type.name if "type" in defectInstance else ""}'
                    issue["filePathname"] = defectInstance.function.fileId.filePathname
                    issue["impact.displayName"] = defectInstance.impact.displayName
                    issueKinds = defectInstance.issueKinds
                    if issueKinds:
                        issue["issueKinds"] = []
                        for issueKind in issueKinds:
                            issue["issueKinds"].append(issueKind.displayName)
                    events = []
                    for event in defectInstance.events:
                        defect_event = {}
                        defect_event["main"] = event.main
                        defect_event["eventKind"] = event.eventKind
                        defect_event["eventNumber"] = event.eventNumber
                        defect_event["eventDescription"] = event.eventDescription
                        defect_event["filePathname"] = event.fileId.filePathname
                        defect_event["lineNumber"] = event.lineNumber
                        defect_event["eventTag"] = event.eventTag
                        if "events" in event:
                            defect_event_subs = []
                            for subevent in event.events:
                                sub_event = {}
                                sub_event["eventNumber"] = subevent.eventNumber
                                sub_event["eventDescription"] = subevent.eventDescription
                                sub_event["filePathname"] = subevent.fileId.filePathname
                                sub_event["lineNumber"] = subevent.lineNumber
                                sub_event["eventTag"] = subevent.eventTag
                                defect_event_subs.append(sub_event)
                            defect_event["sub-events"] = defect_event_subs
                        events.append(defect_event)
                    issue["events"] = events
                    issues.append(issue)
    return issues

#
# Get proejct name for the given stream. Use Coverity API endpoint (/api/v2/streams/).
#
def getProjectNameforStream():
    headers = {'Accept': 'application/json'}
    endpoint = f'/api/v2/streams/{args.stream}?locale=en_us'
    r = requests.get(args.url + endpoint, headers=headers, auth=(args.username, args.password))
    if( r.status_code == 200 ):
        data = json.loads(r.content)
        if(logging.getLogger().isEnabledFor(logging.DEBUG)):
            logging.debug(f'Project name for stream: {args.stream} is {data["streams"][0]["primaryProjectName"]}')
        return data["streams"][0]["primaryProjectName"]
    else:
        raise SystemExit(f'No project name found for stream {args.stream}, error: {r.content}')

def writeToFile(coverityFindingsInSarif):
    f = open(args.outputFile, "w")
    f.write(json.dumps(coverityFindingsInSarif, indent=3))
    f.close()

#
# Main mathod
#
if __name__ == '__main__':
    start = timer()
    result = False
    parser = argparse.ArgumentParser(
        description="CNC Sarif Formatter"
    )
    #Parse commandline arguments
    parser.add_argument('--url', help="Cloud Native Coverity (CNC) URL.", default="", required=True)
    parser.add_argument('--project', help="Coverity project name.", default="")
    parser.add_argument('--stream', help="Coverity stream name.", default="", required=True)
    parser.add_argument('--password', help='User password for Coverity', default="", required=True)
    parser.add_argument('--username', help='Username for Coverity', default="", required=True)
    parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
    parser.add_argument('--impactNameList', help='Comma separated list of impact names for filttering. Options: high, medium, low', default="high, medium, low", required=False)
    parser.add_argument('--statusNamesList', help='Comma separated list of statuses for filttering. Options: New,Triaged,Dismissed,Fixed', default="New,Triaged,Dismissed,Fixed", required=False)
    parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/cncFindings.sarif.json \
                                                if outputfile is not given, then json is printed stdout.", required=False)
    args = parser.parse_args()
    #Initializing the logger
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=args.log_level)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("suds").setLevel(logging.WARNING)
    #Printing out the version number
    logging.info("cncResultstoSarif version: " + __versionro__)
    defectServiceClient = DefectserviceClient(args.url, args.username, args.password).client

    # If project name is not given as a parameter, then it will try to get it with the given stream name.
    project = args.project if args.project else getProjectNameforStream()
    results, rules = getResults(args.stream, project)
    if results and len(results) > 0 and rules and len(rules) > 0:
        results['tool'] = getSarifJsonFooter("CNC", rules)
        runs = []
        runs.append(results)
        sarif_json = getSarifJsonHeader()
        sarif_json['runs'] = runs
        if args.outputFile:
            writeToFile(sarif_json)
        else:
            print(json.dumps(sarif_json, indent=3))
    if(logging.getLogger().isEnabledFor(logging.INFO)):
        end = timer()
        logging.info(f"Checking took: {end - start} seconds.")
