import retirejs as retire
import unittest
import hashlib
from repo import repo

content = "data";
hash = hashlib.sha1(content).hexdigest();


# Some tests might fail because new bugs introduced :( 

class TestingFileContentJS(unittest.TestCase):
	def test1(self):
		result = retire.scanFileContent("/*! jQuery v1.8.1 asdasd ")
		self.assertTrue(retire.isVulnerable(result))
	def test2(self):
		result = retire.scanFileContent("/*! jQuery v1.6.1 asdasd ")
		self.assertTrue(retire.isVulnerable(result))
	def test3(self):
		result = retire.scanFileContent("/*! jQuery v1.12.0 asdasd ")
		self.assertFalse(retire.isVulnerable(result))
	def test4(self):
		result = retire.scanFileContent("/*! jQuery v1.12.1 asdasd ")
		self.assertFalse(retire.isVulnerable(result))
	def test5(self):
		result = retire.scanFileContent("/*! jQuery v1.4 asdasd ")
		self.assertTrue(retire.isVulnerable(result))
	def test6(self):
		result = retire.scanFileContent("a = 1; /*! jQuery v1.4 asdasd ")
		self.assertTrue(retire.isVulnerable(result))


class TestingUri(unittest.TestCase):
	def testuri1(self):
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.8.1/jquery.min.js");
		self.assertTrue(retire.isVulnerable(result))
	def testuri2(self):
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js");
		self.assertTrue(retire.isVulnerable(result))
	def testuri3(self):
		result= retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js");
		self.assertFalse(retire.isVulnerable(result))
	def testuri4(self):
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.12.1/jquery.min.js");
		self.assertFalse(retire.isVulnerable(result))
	def testuri5(self):
		result= retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js");
		self.assertTrue(retire.isVulnerable(result))

class TestingHash(unittest.TestCase):
	
	def testhash1(self):
		global content, hash
		repo["jquery"]["extractors"]["hashes"][hash] = "1.8.1"; 
		result = retire.scanFileContent(content);
		self.assertTrue(retire.isVulnerable(result));
	def testhash2(self):
		repo["jquery"]["extractors"]["hashes"][hash] = "1.6.1"; 
		result = retire.scanFileContent(content);
		self.assertTrue(retire.isVulnerable( result));
	def testhash3(self):
		repo["jquery"]["extractors"]["hashes"][hash] = "1.12.0"; 
		result = retire.scanFileContent(content);
		self.assertFalse(retire.isVulnerable(result));
	def testhash4(self):	
		repo["jquery"]["extractors"]["hashes"][hash] = "1.12.1"; 
		result = retire.scanFileContent(content);
		self.assertFalse(retire.isVulnerable(result));

class TestingFilename(unittest.TestCase):

	def testfilename1(self):
		result = retire.scanFileName("jquery-1.8.1.js");
		self.assertTrue(retire.isVulnerable(result))

	def testfilename2(self):
		result = retire.scanFileName("jquery-2.0.0.js");
		self.assertFalse(retire.isVulnerable(result))

	def testfilename3(self):
		result = retire.scanFileName("jquery-1.12.0.js");
		self.assertFalse(retire.isVulnerable(result))

	def testfilename4(self):
		result = retire.scanFileName("jquery-1.12.1.js");
		self.assertFalse(retire.isVulnerable(result))

	def testfilename5(self):
		result = retire.scanFileName("jquery-1.4.js");
		self.assertTrue(retire.isVulnerable(result))

	def testfilename6(self):
		result = retire.scanFileName("jquery-2.0.0.js");
		self.assertFalse(retire.isVulnerable(result))

	def testfilename7(self):
		result = retire.scanFileName("jquery-1.6.0-rc.1.js");
		self.assertTrue(retire.isVulnerable(result))

	def testfilename8(self):	
		result = retire.scanFileName("jquery-2.0.0-rc.1.1.js");
		self.assertFalse(retire.isVulnerable(result))


class TestingVersion(unittest.TestCase):

	def testVersion1(self):
		repo["jquery"]["vulnerabilities"].append({"below":"10.0.0.beta.2"});
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0/jquery.min.js", repo);
		self.assertFalse(retire.isVulnerable(result))

	def testVersion2(self):
		repo["jquery"]["vulnerabilities"].append({"atOrAbove": "10.0.0-*", "below":"10.0.1"});
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js", repo);
		self.assertTrue(retire.isVulnerable(result))

	def testVersion3(self):
		repo["jquery"]["vulnerabilities"] = [{"below":"10.0.0.beta.2"}];
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.3/jquery.min.js", repo);
		self.assertFalse(retire.isVulnerable(result))

	def testVersion4(self):
		repo["jquery"]["vulnerabilities"] = [{"below":"1.9.0b1"}];
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/1.9.0rc1/jquery.min.js", repo);
		self.assertFalse(retire.isVulnerable(result))
		
	def testVersion5(self):
		repo["jquery"]["vulnerabilities"] = [{"below":"10.0.0.beta.2"}];
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js", repo);
		self.assertFalse(retire.isVulnerable(result))

	def testVersion6(self):
		repo["jquery"]["vulnerabilities"] = [{"below":"10.0.0.beta.2"}];
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js", repo);
		self.assertTrue(retire.isVulnerable(result))
		
	def testVersion7(self):
		repo["jquery"]["vulnerabilities"] = [{"below":"10.0.0"}];
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js", repo);
		self.assertTrue(retire.isVulnerable(result))

	def testVersion8(self):
		repo["jquery"]["vulnerabilities"] = [{"below":"10.0.0"}];
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", repo);
		self.assertTrue(retire.isVulnerable(result))
		
	def testVersion9(self):
		repo["jquery"]["vulnerabilities"] = [{"below":"10.0.0.beta.2"}];
		result = retire.scanUri("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", repo);
		self.assertFalse(retire.isVulnerable(result))


if __name__ == '__main__':
	unittest.main()