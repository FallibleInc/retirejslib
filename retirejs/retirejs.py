import re
from repo import repo
import hashlib
import requests


def isDefined(o) :
	return o != None;


def scan(data, extractor,  matcher=None, repo=repo) :
	matcher = matcher or simpleMatch;
	detected = [];
	for component in repo :
		extractors = repo[component].get("extractors", None).get(extractor, None);
		if (not isDefined(extractors)) :
			continue;
		for i in extractors :
			match = matcher(i, data);
			if (match):
				detected.append({"version": match, "component": component, "detection": extractor });
		
	#print detected
	return detected;


def simpleMatch(regex, data) :
	#print "regex=", regex, "data: ", data
	match = re.search(regex, data)
	# print "match: ", match.group(0)
	# if match:
	# 	print match.group(1)
	return match.group(1) if match else None

def replacementMatch(regex, data) :
	group_parts_of_regex = r'^\/(.*[^\\])\/([^\/]+)\/$'
	ar = re.search(group_parts_of_regex, regex)
	search_for_regex = "(" + ar.group(1) + ")"
	match = re.search(search_for_regex, data)
	ver = None;
	if (match) :
		ver = re.sub(ar.group(1), ar.group(2), match.group(0))
		return ver
	
	return None;



def scanhash(hash, repo=repo) :
	for component in repo :
		hashes = repo[component].get("extractors", None).get("hashes", None);
		if (not isDefined(hashes)):
			continue
		for i in hashes :
			if (i == hash):
				return [{"version": hashes[i], "component": component, "detection": 'hash' }];
		
	
	return [];




def check(results) :
	for r in results :
		result = r

		if (not isDefined(repo[result.get("component", None)])) :
			continue
		vulns = repo[result.get("component", None)].get("vulnerabilities", None);
		for i in xrange(len(vulns)) :
			if (not isAtOrAbove(result.get("version", None), vulns[i].get("below", None))) :
				if (isDefined(vulns[i].get("atOrAbove", None)) and not isAtOrAbove(result.get("version", None), vulns[i].get("atOrAbove", None))) :
					continue
				
				vulnerability = {"info" : vulns[i].get("info", None) }
				if (vulns[i].get("severity", None)) :
					vulnerability["severity"] = vulns[i].get("severity", None)
				
				if (vulns[i].get("identifiers", None)) :
					vulnerability["identifiers"] = vulns[i].get("identifiers", None);
				
				result["vulnerabilities"] = result.get("vulnerabilities", None) or [];
				result["vulnerabilities"].append(vulnerability)
			
		
	return results;


def unique(ar) :
	return list(set(ar));



def isAtOrAbove(version1, version2) :
	#print "[",version1,",", version2,"]"
	v1 = re.split(r'[.-]', version1)
	v2 = re.split(r'[.-]', version2)

	l = len(v1) if len(v1) > len(v2) else len(v2);
	for i in xrange(l) :
		v1_c = toComparable(v1[i] if len(v1) > i else None);
		v2_c = toComparable(v2[i] if len(v2) > i else None);
		#print v1_c, "vs", v2_c
		if (type(v1_c) != type(v2_c)):
			return type(v1_c) == int;
		if (v1_c > v2_c):
			return True;
		if (v1_c < v2_c):
			return False;
	
	return True;


def toComparable(n) :
	if (not isDefined(n)) :
		return 0;
	# todo check regex [one check done]
	if (re.search(r'^[0-9]+$', n)) :
		# print re.group(0)
		return int(str(n), 10)
	
	return n;



#------- External API -------

# def check(component, version) :
# 	return check([{"component": component, "version": version}]);


def replaceVersion(jsRepoJsonAsText) :
	return re.sub(r'[.0-9]*', '[0-9][0-9.a-z_\-]+', jsRepoJsonAsText);


def isVulnerable(results) :
	for r in results :
		if ('vulnerabilities' in r):
			# print r
			return True
	
	return False


def scanUri(uri, repo=repo) :
	result = scan(uri, 'uri', repo=repo);
	return check(result);


def scanFileName(fileName, repo=repo) :
	result = scan(fileName, 'filename', repo=repo);
	return check(result);


def scanFileContent(content, repo=repo) :
	result = scan(content, 'filecontent', repo=repo);
	if (len(result) == 0) :
		result = scan(content, 'filecontentreplace',  replacementMatch, repo);
	
	if (len(result) == 0) :
		result = scanhash(hashlib.sha1(content).hexdigest(), repo);
	
	return check(result);

def scan_endpoint(uri, repo=repo):
	"""
	Given a uri it scans for vulnerability in uri and the content
	hosted at that uri
	"""
	uri_scan_result = scanUri(uri, repo)

	filecontent = requests.get(uri, verify=False).text
	filecontent_scan_result = scanFileContent(filecontent, repo)

	return uri_scan_result.extend(filecontent_scan_result)

	
