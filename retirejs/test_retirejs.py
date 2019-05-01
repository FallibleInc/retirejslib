import retirejs as retire
import unittest
import hashlib
from vulnerabilities import definitions

content = "data"
hash = hashlib.sha1(content.encode("utf-8")).hexdigest()


# Some tests might fail because new bugs introduced :(

class TestingFileContentJS(unittest.TestCase):

    def test1(self):
        result = retire.scan_file_content("/*! jQuery v1.8.1 asdasd ")
        self.assertTrue(retire.is_vulnerable(result))

    def test2(self):
        result = retire.scan_file_content("/*! jQuery v1.6.1 asdasd ")
        self.assertTrue(retire.is_vulnerable(result))

    def test3(self):
        result = retire.scan_file_content("/*! jQuery v1.12.0 asdasd ")
        self.assertFalse(retire.is_vulnerable(result))

    def test4(self):
        result = retire.scan_file_content("/*! jQuery v1.12.1 asdasd ")
        self.assertFalse(retire.is_vulnerable(result))

    def test5(self):
        result = retire.scan_file_content("/*! jQuery v1.4 asdasd ")
        self.assertTrue(retire.is_vulnerable(result))

    def test6(self):
        result = retire.scan_file_content("a = 1; /*! jQuery v1.4 asdasd ")
        self.assertTrue(retire.is_vulnerable(result))


class TestingUri(unittest.TestCase):

    def testuri1(self):
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/1.8.1/jquery.min.js")
        self.assertTrue(retire.is_vulnerable(result))

    def testuri2(self):
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js")
        self.assertTrue(retire.is_vulnerable(result))

    def testuri3(self):
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js")
        self.assertFalse(retire.is_vulnerable(result))

    def testuri4(self):
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/1.12.1/jquery.min.js")
        self.assertFalse(retire.is_vulnerable(result))

    def testuri5(self):
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js")
        self.assertTrue(retire.is_vulnerable(result))


class TestingHash(unittest.TestCase):

    def testhash1(self):
        global content, hash
        definitions["jquery"]["extractors"]["hashes"][hash] = "1.8.1"
        result = retire.scan_file_content(content)
        self.assertTrue(retire.is_vulnerable(result))

    def testhash2(self):
        definitions["jquery"]["extractors"]["hashes"][hash] = "1.6.1"
        result = retire.scan_file_content(content)
        self.assertTrue(retire.is_vulnerable(result))

    def testhash3(self):
        definitions["jquery"]["extractors"]["hashes"][hash] = "1.12.0"
        result = retire.scan_file_content(content)
        self.assertFalse(retire.is_vulnerable(result))

    def testhash4(self):
        definitions["jquery"]["extractors"]["hashes"][hash] = "1.12.1"
        result = retire.scan_file_content(content)
        self.assertFalse(retire.is_vulnerable(result))


class TestingFilename(unittest.TestCase):

    def testfilename1(self):
        result = retire.scan_filename("jquery-1.8.1.js")
        self.assertTrue(retire.is_vulnerable(result))

    def testfilename2(self):
        result = retire.scan_filename("jquery-2.0.0.js")
        self.assertTrue(retire.is_vulnerable(result))

    def testfilename3(self):
        result = retire.scan_filename("jquery-1.12.0.js")
        self.assertFalse(retire.is_vulnerable(result))

    def testfilename4(self):
        result = retire.scan_filename("jquery-1.12.1.js")
        self.assertFalse(retire.is_vulnerable(result))

    def testfilename5(self):
        result = retire.scan_filename("jquery-1.4.js")
        self.assertTrue(retire.is_vulnerable(result))

    def testfilename6(self):
        result = retire.scan_filename("jquery-1.6.0-rc.1.js")
        self.assertTrue(retire.is_vulnerable(result))

    def testfilename7(self):
        result = retire.scan_filename("jquery-2.0.0-rc.1.1.js")
        self.assertTrue(retire.is_vulnerable(result))


class TestingVersion(unittest.TestCase):

    def testVersion1(self):
        definitions["jquery"]["vulnerabilities"].append({"below": "10.0.0.beta.2"})
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0/jquery.min.js", definitions)
        self.assertFalse(retire.is_vulnerable(result))

    def testVersion2(self):
        definitions["jquery"]["vulnerabilities"].append(
            {"atOrAbove": "10.0.0-*", "below": "10.0.1"})
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js",
            definitions)
        self.assertTrue(retire.is_vulnerable(result))

    def testVersion3(self):
        definitions["jquery"]["vulnerabilities"] = [{"below": "10.0.0.beta.2"}]
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.3/jquery.min.js",
            definitions)
        self.assertFalse(retire.is_vulnerable(result))

    def testVersion4(self):
        definitions["jquery"]["vulnerabilities"] = [{"below": "1.9.0b1"}]
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/1.9.0rc1/jquery.min.js", definitions)
        self.assertFalse(retire.is_vulnerable(result))

    def testVersion5(self):
        definitions["jquery"]["vulnerabilities"] = [{"below": "10.0.0.beta.2"}]
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js",
            definitions)
        self.assertFalse(retire.is_vulnerable(result))

    def testVersion6(self):
        definitions["jquery"]["vulnerabilities"] = [{"below": "10.0.0.beta.2"}]
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js",
            definitions)
        self.assertTrue(retire.is_vulnerable(result))

    def testVersion7(self):
        definitions["jquery"]["vulnerabilities"] = [{"below": "10.0.0"}]
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js",
            definitions)
        self.assertTrue(retire.is_vulnerable(result))

    def testVersion8(self):
        definitions["jquery"]["vulnerabilities"] = [{"below": "10.0.0"}]
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", definitions)
        self.assertTrue(retire.is_vulnerable(result))

    def testVersion9(self):
        definitions["jquery"]["vulnerabilities"] = [{"below": "10.0.0.beta.2"}]
        result = retire.scan_uri(
            "https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", definitions)
        self.assertFalse(retire.is_vulnerable(result))


if __name__ == '__main__':
    unittest.main()
