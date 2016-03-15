repo = {
	"retire-example": {
		"vulnerabilities" : [
			{
				"below" : "0.0.2",
				"severity" : "low",
				"identifiers" : {
					"CVE" : [ "CVE-XXXX-XXXX" ],
					"bug" : "1234",
					"summary" : "bug summary"
				},
				"info" : [ "http://github.com/eoftedal/retire.js/" ]
			}
		],
		"extractors" : {
			"func" : [ "retire.VERSION" ],
			"filename" : [ "retire-example-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ "/\*!? Retire-example v([0-9][0-9.a-z_\-]+)" ],
			"hashes" : { "07f8b94c8d601a24a1914a1a92bec0e4fafda964" : "0.0.1" }
		}
	},

	"jquery": {
		"vulnerabilities" : [
			{
				"below" : "1.6.3",
				"severity" : "medium",
				"identifiers" : { "CVE": [ "CVE-2011-4969" ] },
				"info" : [ "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-4969" , "http://research.insecurelabs.org/jquery/test/" ]
			},
			{
				"below" : "1.9.0b1",
				"identifiers": {
					"bug": "11290",
					"summary": "Selector interpreted as HTML"
				},
				"severity": "medium",
				"info" : [ "http://bugs.jquery.com/ticket/11290" , "http://research.insecurelabs.org/jquery/test/" ]
			},
			{
				"below" : "1.12.0",
				"identifiers": {
					"summary": "3rd party CORS request may execute"
				},
				"severity": "medium",
				"info" : [ "https://github.com/jquery/jquery/issues/2432", "http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/" ]
			}
		],
		"extractors" : {
			"func"    		: [ "/[0-9.]+/.test(jQuery.fn.jquery) ? jQuery.fn.jquery : undefined" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/jquery(\.min)?\.js" ],
			"filename"		: [ "jquery-([0-9][0-9.a-z_\-]+)(\.min)?\.js" ],
			"filecontent"	: [
								"/\*!? jQuery v([0-9][0-9.a-z_\-]+)", "\* jQuery JavaScript Library v([0-9][0-9.a-z_\-]+)",
								"\* jQuery ([0-9][0-9.a-z_\-]+) - New Wave Javascript", "// \$Id: jquery.js,v ([0-9][0-9.a-z_\-]+)",
								"/\*! jQuery v([0-9][0-9.a-z_\-]+)",
                                                                "[^a-z]f=\"([0-9][0-9.a-z_\-]+)\",.*[^a-z]jquery:f,",
                                                                "[^a-z]m=\"([0-9][0-9.a-z_\-]+)\",.*[^a-z]jquery:m,",
                                                                "[^a-z.]jquery:[ ]?\"([0-9][0-9.a-z_\-]+)\""
								],
			"hashes"		: {}
		}
	},
	"jquery-migrate" : {
		"vulnerabilities" : [
			{
				"below" : "1.2.0",
				"severity": "medium",
				"identifiers": {
					"release": "jQuery Migrate 1.2.0 Released",
					"summary": "cross-site-scripting"
				},
				"info" : [ "http://blog.jquery.com/2013/05/01/jquery-migrate-1-2-0-released/" ]
			},
			{
				"below" : "1.2.2",
				"severity": "medium",
				"identifiers": {
					"bug": "11290",
					"summary": "Selector interpreted as HTML"
				},
				"info" : [ "http://bugs.jquery.com/ticket/11290" , "http://research.insecurelabs.org/jquery/test/" ]
			}
		],
		"extractors" : {
			"filename"		: [ "jquery-migrate-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ "/\*!?(?:\n \*)? jQuery Migrate(?: -)? v([0-9][0-9.a-z_\-]+)" ],
			"hashes"		: {}
		}
	},
	"jquery-mobile" : {
		"vulnerabilities" : [
			{
				"below" : "1.0RC2",
				"severity": "high",
				"identifiers": {"osvdb": ["94563", "93562", "94316", "94561", "94560"]},
				"info" : [ "http://osvdb.org/show/osvdb/94563", "http://osvdb.org/show/osvdb/94562", "http://osvdb.org/show/osvdb/94316", "http://osvdb.org/show/osvdb/94561", "http://osvdb.org/show/osvdb/94560" ]
			},
			{
				"below" : "1.0.1",
				"severity": "high",
				"identifiers": {"osvdb": "94317"},
				"info": [ "http://osvdb.org/show/osvdb/94317" ]
			},
			{
				"below" : "1.1.2",
				"severity": "medium",
				"identifiers": {
					"issue": "4787",
					"release": "http://jquerymobile.com/changelog/1.1.2/",
					"summary": "location.href cross-site scripting"
				},
				"info": [ "http://jquerymobile.com/changelog/1.1.2/", "https://github.com/jquery/jquery-mobile/issues/4787" ]
			},
			{
				"below" : "1.2.0",
				"severity": "medium",
				"identifiers": {
					"issue": "4787",
					"release": "http://jquerymobile.com/changelog/1.2.0/",
					"summary": "location.href cross-site scripting"
				},
				"info": [ "http://jquerymobile.com/changelog/1.2.0/", "https://github.com/jquery/jquery-mobile/issues/4787" ]
			}
		],
		"extractors" : {
			"func"    		: [ "jQuery.mobile.version" ],
			"filename"		: [ "jquery.mobile-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/jquery.mobile(\.min)?\.js" ],
			"filecontent"	: [ "/\*!?(?:\n \*)? jQuery Mobile(?: -)? v([0-9][0-9.a-z_\-]+)" ],
			"hashes"		: {}
		}
	},
	"jquery-ui-dialog" : {
		"vulnerabilities" : [
			{
				"atOrAbove": "1.8.9",
				"below" : "1.10.0",
				"severity": "medium",
				"identifiers": {
					"bug": "6016",
					"summary": "Title cross-site scripting vulnerability"
				},
				"info" : [ "http://bugs.jqueryui.com/ticket/6016" ]
			}
		],
		"extractors" : {
			"func"    		: [ "jQuery.ui.dialog.version" ],
			"filecontent"	: [
				"/\*!? jQuery UI - v([0-9][0-9.a-z_\-]+)(.*\n){1,3}.*jquery\.ui\.dialog\.js",
				"/\*!?[\n *]+jQuery UI ([0-9][0-9.a-z_\-]+)(.*\n)*.*\.ui\.dialog",
				"/\*!?[\n *]+jQuery UI Dialog ([0-9][0-9.a-z_\-]+)"
			],
			"hashes"		: {}
		}
	},
	"jquery-ui-autocomplete" : {
		"vulnerabilities" : [ ],
		"extractors" : {
			"func"    		: [ "jQuery.ui.autocomplete.version" ],
			"filecontent"	: [
				"/\*!? jQuery UI - v([0-9][0-9.a-z_\-]+)(.*\n){1,3}.*jquery\.ui\.autocomplete\.js",
				"/\*!?[\n *]+jQuery UI ([0-9][0-9.a-z_\-]+)(.*\n)*.*\.ui\.autocomplete",
				"/\*!?[\n *]+jQuery UI Autocomplete ([0-9][0-9.a-z_\-]+)"
			],
			"hashes"		: {}
		}
	},
	"jquery-ui-tooltip" : {
		"vulnerabilities" : [
			{
				"atOrAbove": "1.9.2",
				"below" : "1.10.0",
				"severity": "high",
				"identifiers": {
					"bug": "8859",
					"summary": "Autocomplete cross-site scripting vulnerability"
				},
				"info" : [ "http://bugs.jqueryui.com/ticket/8859" ]
			}
		],
		"extractors" : {
			"func"    		: [ "jQuery.ui.tooltip.version" ],
			"filecontent"	: [
				"/\*!? jQuery UI - v([0-9][0-9.a-z_\-]+)(.*\n){1,3}.*jquery\.ui\.tooltip\.js",
				"/\*!?[\n *]+jQuery UI ([0-9][0-9.a-z_\-]+)(.*\n)*.*\.ui\.tooltip",
				"/\*!?[\n *]+jQuery UI Tooltip ([0-9][0-9.a-z_\-]+)"
			],
			"hashes"		: {}
		}
	},
	"jquery.prettyPhoto" : {
		"vulnerabilities" : [
			{
				"below" : "3.1.5",
				"severity" : "high",
				"identifiers" : { "CVE" : [ "CVE-2013-6837" ] },
				"info" : [ "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-6837&cid=3" ]
			},
			{
				"below" : "3.1.6",
				"severity" : "high",
				"info" : [ "https://github.com/scaron/prettyphoto/issues/149", "https://blog.anantshri.info/forgotten_disclosure_dom_xss_prettyphoto" ]
			}

		],
		"extractors" : {
			"func"    		: [ "jQuery.prettyPhoto.version" ],
			"filecontent"	: [
				"/\*(?:.*[\n\r]+){1,3}.*Class: prettyPhoto(?:.*[\n\r]+){1,3}.*Version: ([0-9][0-9.a-z_\-]+)",
				"\.prettyPhoto[ ]?=[ ]?\{version:[ ]?(?:'|\")([0-9][0-9.a-z_\-]+)(?:'|\")\}"
			],
			"hashes"		: {}
		}
	},
	"jPlayer" : {
		"vulnerabilities" : [
			{
				"below" : "2.4.0",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2013-2023" ]},
				"info" : [ "http://jplayer.org/latest/release-notes/", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2023" ]
			},
			{
				"below" : "2.3.0",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2013-1942", "CVE-2013-2022"]},
				"info" : [ "http://jplayer.org/latest/release-notes/", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1942", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2022" ]
			},
			{
				"below" : "2.2.0",
				"severity": "high",
				"identifiers": {
					"release": "2.2.0",
					"summary": "Flash SWF vulnerability"
				},
				"info" : [ "http://jplayer.org/latest/release-notes/" ]
			}
		],
		"extractors" : {
			"func"    		: [ "new jQuery.jPlayer().version.script" ],
			"filecontent"	: [
				"/\*(?:.*[\n\r]+){1,3}.*jPlayer Plugin for jQuery(?:.*[\n\r]+){1,10}.*Version: ([0-9][0-9.a-z_\-]+)"
			],
			"hashes"		: {}
		}
	},
	"sessvars": {
		"vulnerabilities" : [
			{
				"below" : "1.01",
				"severity": "low",
				"identifiers": {"summary": "Unsanitized data passed to eval()"},
				"info" : [ "http://www.thomasfrank.se/sessionvars.html" ]
			}
		],
		"extractors" : {
			"filename"		: [ "sessvars-([0-9][0-9.a-z_\-]+)(.min)?\.js"],
			"filecontent"	: [ "sessvars ver ([0-9][0-9.a-z_\-]+)"],
			"hashes"		: {}
		}
	},
	"swfobject": {
		"vulnerabilities" : [
			{
				"below" : "2.1",
				"severity": "medium",
				"identifiers": {"summary": "DOM-based XSS"},
				"info" : [ "https://code.google.com/p/swfobject/wiki/release_notes", "https://code.google.com/p/swfobject/source/detail?r=181" ]
			}
		],
		"extractors" : {
			"filename"		: [ "swfobject_([0-9][0-9.a-z_\-]+)(.min)?\.js"],
			"filecontent"	: [ "SWFObject v([0-9][0-9.a-z_\-]+) "],
			"hashes"		: {}
		}
	},

	"tinyMCE" : {
		"vulnerabilities" : [
			{
				"below" : "1.4.2",
				"serverity" : "high",
				"identifiers" : {
					"summary" : "Static code injection vulnerability in inc/function.base.php", 
					"CVE" : "CVE-2011-4825"
				},
				"info" : [ "http://www.cvedetails.com/cve/CVE-2011-4825/" ]
			},
			{
				"below" : "4.2.4",
				"serverity" : "medium",
				"identifiers" : { "summary" : "xss issues with media plugin not properly filtering out some script attributes." },
				"info" : [ "https://www.tinymce.com/docs/changelog/" ]

			},
			{
				"below" : "4.2.0",
				"serverity" : "medium",
				"identifiers" : { "summary" : "FIXED so script elements gets removed by default to prevent possible XSS issues in default config implementations" },
				"info" : [ "https://www.tinymce.com/docs/changelog/" ]

			}
		],
		"extractors" : {
			"filecontent"	       : [ "// ([0-9][0-9.a-z_\-]+) \([0-9\-]+\)[\n\r]+.{0,1200}l=.tinymce/geom/Rect." ],
			"filecontentreplace" : [ "/tinyMCEPreInit.*majorVersion:.([0-9]+).,minorVersion:.([0-9.]+)./$1.$2/" ],
			"func" 				       : [ "tinyMCE.majorVersion + '.'+ tinyMCE.minorVersion" ]
		}
	},

	"YUI" : {
		"vulnerabilities" : [
			{
				"atOrAbove" : "3.5.0" ,
				"below" : "3.9.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2013-4942" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2013-4942/" ]
			},
			{
				"atOrAbove" : "3.2.0" ,
				"below" : "3.9.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2013-4941" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2013-4941/" ]
			},
			{
				"below" : "3.10.3",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2013-4940" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2013-4940/" ]
			},
			{
				"atOrAbove" : "3.0.0" ,
				"below" : "3.9.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2013-4939" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2013-4939/" ]
			},
			{
				"atOrAbove" : "2.8.0" ,
				"below" : "2.9.1",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2012-5883" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2012-5883/" ]
			},
			{
				"atOrAbove" : "2.5.0" ,
				"below" : "2.9.1",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2012-5882" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2012-5882/" ]
			},
			{
				"atOrAbove" : "2.4.0" ,
				"below" : "2.9.1",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2012-5881" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2012-5881/" ]
			},
			{
				"below" : "2.9.0",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2010-4710" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2010-4710/" ]
			},
			{
				"atOrAbove" : "2.8.0" ,
				"below" : "2.8.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2010-4209" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2010-4209/" ]
			},
			{
				"atOrAbove" : "2.5.0" ,
				"below" : "2.8.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2010-4208" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2010-4208/" ]
			},
			{
				"atOrAbove" : "2.4.0" ,
				"below" : "2.8.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2010-4207" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2010-4207/" ]
			}
		],
		"extractors" : {
			"func"    		: [ "YUI.Version", "YAHOO.VERSION" ],
			"filename"		: [ "yui-([0-9][0-9.a-z_\-]+)(.min)?\.js"],
			"filecontent"	: [ "/*\nYUI ([0-9][0-9.a-z_\-]+)", "/yui/license.(?:html|txt)\nversion: ([0-9][0-9.a-z_\-]+)"],
			"hashes"		: {}
		}
	},
	"prototypejs" : {
		"vulnerabilities" : [
			{
				"atOrAbove" : "1.6.0",
				"below" : "1.6.0.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2008-7220" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2008-7220/" ] },
			{
				"below" : "1.5.1.2",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2008-7220" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2008-7220/" ] }
		],
		"extractors" : {
			"func"    		: [ "Prototype.Version" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/prototype(\.min)?\.js" ],
			"filename"		: [ "prototype-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ "Prototype JavaScript framework, version ([0-9][0-9.a-z_\-]+)",
								"Prototype[ ]?=[ ]?\{[ \r\n\t]*Version:[ ]?(?:'|\")([0-9][0-9.a-z_\-]+)(?:'|\")" ],
			"hashes"		: {}
		}
	},
	"ember" : {
		"vulnerabilities" : [
			{ 
				"atOrAbove" : "1.8.0",
				"below" :"1.11.4",
				"severity" : "medium",
				"identifiers": {"CVE": "CVE-2015-7565"},
				"info": [ "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY" ]
			},
			{ 
				"atOrAbove" : "1.12.0",
				"below" :"1.12.2",
				"severity" : "medium",
				"identifiers": {"CVE": "CVE-2015-7565"},
				"info": [ "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY" ]
			},
			{ 
				"atOrAbove" : "1.13.0",
				"below" : "1.13.12",
				"severity" : "medium",
				"identifiers": {"CVE": "CVE-2015-7565"},
				"info": [ "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY" ]
			},
			{ 
				"atOrAbove" : "2.0.0",
				"below" : "2.0.3",
				"severity" : "medium",
				"identifiers": {"CVE": "CVE-2015-7565"},
				"info": [ "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY" ]
			},
			{ 
				"atOrAbove" : "2.1.0",
				"below" : "2.1.2",
				"severity" : "medium",
				"identifiers": {"CVE": "CVE-2015-7565" },
				"info": [ "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY" ]
			},
			{ 
				"atOrAbove" : "2.2.0",
				"below" : "2.2.1",
				"severity" : "medium",
				"identifiers": {"CVE": "CVE-2015-7565"},
				"info": [ "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY" ]
			},
			{
				"below" : "1.5.0",
				"severity": "medium",
				"identifiers": {
					"CVE": [ "CVE-2014-0046" ],
					"summary": "ember-routing-auto-location can be forced to redirect to another domain"
				},
				"info" : [ "https://github.com/emberjs/ember.js/blob/v1.5.0/CHANGELOG.md" ]
			},
			{
				"atOrAbove" : "1.3.0-*",
				"below" : "1.3.2",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2014-0046" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ" ]
			},
			{
				"atOrAbove" : "1.2.0-*",
				"below" : "1.2.2",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2014-0046" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ" ] },
			{
				"atOrAbove" : "1.4.0-*",
				"below" : "1.4.0-beta.2",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2014-0013", "CVE-2014-0014"]},
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4" ]
			},
			{
				"atOrAbove" : "1.3.0-*",
				"below" : "1.3.1",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2014-0013", "CVE-2014-0014"]},
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4" ]
			},
			{
				"atOrAbove" : "1.2.0-*",
				"below" : "1.2.1",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2014-0013", "CVE-2014-0014"]},
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4" ]
			},
			{
				"atOrAbove" : "1.1.0-*",
				"below" : "1.1.3",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2014-0013", "CVE-2014-0014"]},
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4" ]
			},
			{
				"atOrAbove" : "1.0.0-*",
				"below" : "1.0.1",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2014-0013", "CVE-2014-0014"]},
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4" ]
			},
			{
				"atOrAbove" : "1.0.0-rc.1",
				"below" : "1.0.0-rc.1.1",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2013-4170" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM" ]
			},
			{
				"atOrAbove" : "1.0.0-rc.2",
				"below" : "1.0.0-rc.2.1",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2013-4170" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM" ]
			},
			{
				"atOrAbove" : "1.0.0-rc.3",
				"below" : "1.0.0-rc.3.1",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2013-4170" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM" ]
			},
			{
				"atOrAbove" : "1.0.0-rc.4",
				"below" : "1.0.0-rc.4.1",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2013-4170" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM" ]
			},
			{
				"atOrAbove" : "1.0.0-rc.5",
				"below" : "1.0.0-rc.5.1",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2013-4170" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM" ]
			},
			{
				"atOrAbove" : "1.0.0-rc.6",
				"below" : "1.0.0-rc.6.1",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2013-4170" ] },
				"info" : [ "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM" ]
			},
			{
				"below" : "0.9.7.1",
				"info" : [ "https://github.com/emberjs/ember.js/blob/master/CHANGELOG" ]
			},
			{
				"below" : "0.9.7",
				"severity": "high",
				"identifiers": {
					"bug": "699",
					"summary": "Bound attributes aren't escaped properly"
				},
				"info" : [ "https://github.com/emberjs/ember.js/issues/699" ]
			}
		],
		"extractors" : {
			"func"			: [ "Ember.VERSION" ],
			"uri"			: [ "/(?:v)?([0-9][0-9.a-z_\-]+)/ember(\.min)?\.js" ],
			"filename"		: [ "ember-([0-9][0-9.a-z_\-]+)(\.min)?\.js" ],
			"filecontent"	: [
				"Project:   Ember -(?:.*\n){9,11}// Version: v([0-9][0-9.a-z_\-]+)",
				"// Version: v([0-9][0-9.a-z_\-]+)(.*\n){10,15}(Ember Debug|@module ember|@class ember)",
				"Ember.VERSION[ ]?=[ ]?(?:'|\")([0-9][0-9.a-z_\-]+)(?:'|\")"
			],
			"hashes"		: {}
		}
	},
	"dojo" : {
		"vulnerabilities" : [
			{
				"atOrAbove" : "0.4",
				"below" : "0.4.4",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2010-2276", "CVE-2010-2272"]},
				"info" : [ "http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2272/" ]
			},
			{
				"atOrAbove" : "1.0",
				"below" : "1.0.3",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"]},
				"info" : [ "http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/" ]
			},
			{
				"atOrAbove" : "1.1",
				"below" : "1.1.2",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"]},
				"info" : [ "http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/" ]
			},
			{
				"atOrAbove" : "1.2",
				"below" : "1.2.4",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"]},
				"info" : [ "http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/" ]
			},
			{
				"atOrAbove" : "1.3",
				"below" : "1.3.3",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"]},
				"info" : [ "http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/" ]
			},
			{
				"atOrAbove" : "1.4",
				"below" : "1.4.2",
				"severity": "high",
				"identifiers": {"CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"]},
				"info" : [ "http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/" ]
			},
			{
				"below" : "1.4.2",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2010-2275" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2010-2275/"]
			},
			{
				"below" : "1.1",
				"severity": "medium",
				"identifiers": {"CVE": [ "CVE-2008-6681" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2008-6681/"]
			}


		],
		"extractors" : {
			"func"				 : [ "dojo.version.toString()" ],
			"uri"				 : [ "/(?:dojo-)?([0-9][0-9.a-z_\-]+)/dojo(\.min)?\.js" ],
			"filename"			 : [ "dojo-([0-9][0-9.a-z_\-]+)(\.min)?\.js" ],
			"filecontentreplace" : [ "/dojo.version=\{major:([0-9]+),minor:([0-9]+),patch:([0-9]+)/$1.$2.$3/"],
			"hashes"			 : {
				"73cdd262799aab850abbe694cd3bfb709ea23627" : "1.4.1",
				"c8c84eddc732c3cbf370764836a7712f3f873326" : "1.4.0",
				"d569ce9efb7edaedaec8ca9491aab0c656f7c8f0" : "1.0.0",
				"ad44e1770895b7fa84aff5a56a0f99b855a83769" : "1.3.2",
				"8fc10142a06966a8709cd9b8732f7b6db88d0c34" : "1.3.1",
				"a09b5851a0a3e9d81353745a4663741238ee1b84" : "1.3.0",
				"2ab48d45abe2f54cdda6ca32193b5ceb2b1bc25d" : "1.2.3",
				"12208a1e649402e362f528f6aae2c614fc697f8f" : "1.2.0",
				"72a6a9fbef9fa5a73cd47e49942199147f905206" : "1.1.1"
			}

		}
	},
	"angularjs" : {
		"vulnerabilities" : [
			{
				"below" : "1.2.0",
				"severity": "high",
				"identifiers": {
					"summary": [
						"execution of arbitrary javascript",
						"sandboxing fails",
						"possible cross-site scripting vulnerabilities"
					]
				},
				"info" : [ "https://code.google.com/p/mustache-security/wiki/AngularJS" ]
			},
			{
				"below" : "1.2.19",
				"severity": "medium",
				"identifiers": {
					"release": "1.3.0-beta.14",
					"summary": "execution of arbitrary javascript"
				},
				"info" : [ "https://github.com/angular/angular.js/blob/b3b5015cb7919708ce179dc3d6f0d7d7f43ef621/CHANGELOG.md" ]
			},
			{
				"below" : "1.2.24",
				"severity": "medium",
				"identifiers": {
					"commit": "b39e1d47b9a1b39a9fe34c847a81f589fba522f8",
					"summary": "execution of arbitrary javascript"
				},
				"info" : [ "http://avlidienbrunn.se/angular.txt", "https://github.com/angular/angular.js/commit/b39e1d47b9a1b39a9fe34c847a81f589fba522f8"]
			},
			{
				"atOrAbove" : "1.3.0-beta.1",
				"below" : "1.3.0-beta.14",
				"severity": "medium",
				"identifiers": {
					"commit": "b39e1d47b9a1b39a9fe34c847a81f589fba522f8",
					"summary": "execution of arbitrary javascript"
				},
				"info" : [ "https://github.com/angular/angular.js/blob/b3b5015cb7919708ce179dc3d6f0d7d7f43ef621/CHANGELOG.md" ]
			},
			{
				"atOrAbove" : "1.3.0-beta.1",
				"below" : "1.3.0-rc.1",
				"severity": "medium",
				"identifiers": {
					"commit": "b39e1d47b9a1b39a9fe34c847a81f589fba522f8",
					"summary": "execution of arbitrary javascript"
				},
				"info" : [ "http://avlidienbrunn.se/angular.txt", "https://github.com/angular/angular.js/commit/b39e1d47b9a1b39a9fe34c847a81f589fba522f8"]
			},
			{
				"below" : "1.3.2",
				"severity": "low",
				"identifiers": {
					"summary": "server-side xss can bypass CSP"
				},
				"info" : [ "https://github.com/angular/angular.js/blob/master/CHANGELOG.md" ]
			},
			{
				"below" : "1.5.0-rc.2",
				"severity": "low",
				"identifiers": {
					"summary": "server-side xss can bypass CSP"
				},
				"info" : [ "https://github.com/angular/angular.js/blob/master/CHANGELOG.md" ]
			}

		],
		"extractors" : {
			"func"			: [ "angular.version.full" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/angular(\.min)?\.js" ],
			"filename"		: [ "angular(?:js)?-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ 
				"/\*[ \n]+AngularJS v([0-9][0-9.a-z_\-]+)",
				"http://errors\.angularjs\.org/([0-9][0-9.a-z_\-]+)/"
			],
			"hashes"		: {}
		}
	},
	"backbone.js" : {
		"vulnerabilities" : [
			{
				"below" : "0.5.0",
				"severity": "medium",
				"identifiers": {
					"release": "0.5.0",
					"summary": "cross-site scripting vulnerability"
				},
				"info" : [ "http://backbonejs.org/#changelog" ]
			}
		],
		"extractors" : {
			"func"			: [ "Backbone.VERSION" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/backbone(\.min)?\.js" ],
			"filename"		: [ "backbone(?:js)?-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ "//[ ]+Backbone.js ([0-9][0-9.a-z_\-]+)", "a=t.Backbone={}}a.VERSION=\"([0-9][0-9.a-z_\-]+)\"" ],
			"hashes"		: {}
		}
	},
	"mustache.js" : {
		"vulnerabilities" : [
			{
				"below" : "0.3.1",
				"severity": "high",
				"identifiers": {
					"bug": "112",
					"summary": "execution of arbitrary javascript"
				},
				"info" : [ "https://github.com/janl/mustache.js/issues/112" ] 
			},
			{
				"below" : "2.2.1",
				"severity": "medium",
				"identifiers": {
					"bug": "pull request 530",
					"summary": "weakness in HTML escaping"
				},
				"info" : [ "https://github.com/janl/mustache.js/releases/tag/v2.2.1", "https://github.com/janl/mustache.js/pull/530" ] 
			} 
		],
		"extractors" : {
			"func"			: [ "Mustache.version" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/mustache(\.min)?\.js" ],
			"filename"		: [ "mustache(?:js)?-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ "name:\"mustache.js\",version:\"([0-9][0-9.a-z_\-]+)\"",
								"[^a-z]mustache.version[ ]?=[ ]?(?:'|\")([0-9][0-9.a-z_\-]+)(?:'|\")",
								"exports.name[ ]?=[ ]?\"mustache.js\";[\n ]*exports.version[ ]?=[ ]?(?:'|\")([0-9][0-9.a-z_\-]+)(?:'|\");"
								],
			"hashes"		: {}
		}
	},
	"handlebars.js" : {
		"vulnerabilities" : [
			{
				"below" : "1.0.0.beta.3",
				"severity": "medium",
				"identifiers": {
					"summary": "poorly sanitized input passed to eval()"
				},
				"info" : [ "https://github.com/wycats/handlebars.js/pull/68" ] 
			},
			{
				"below" : "4.0.0",
				"severity": "medium",
				"identifiers": {
					"summary": "Quoteless attributes in templates can lead to XSS"
				},
				"info" : [ "https://github.com/wycats/handlebars.js/pull/1083" ] 
			}
		],
		"extractors" : {
			"func"			: [ "Handlebars.VERSION" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/handlebars(\.min)?\.js" ],
			"filename"		: [ "handlebars(?:js)?-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ "Handlebars.VERSION = \"([0-9][0-9.a-z_\-]+)\";", "Handlebars=\{VERSION:(?:'|\")([0-9][0-9.a-z_\-]+)(?:'|\")",
								"this.Handlebars=\{\};[\n\r \t]+\(function\([a-z]\)\{[a-z].VERSION=(?:'|\")([0-9][0-9.a-z_\-]+)(?:'|\")"
								],
			"hashes"		: {}
		}
	},
	"easyXDM" : {
		"vulnerabilities" : [
			{
				"below" : "2.4.18",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2013-5212" ] },
				"info" : [ "http://blog.kotowicz.net/2013/09/exploiting-easyxdm-part-1-not-usual.html", "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5212" ]
			},
			{
				"below" : "2.4.19",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2014-1403" ] },
				"info" : [ "http://blog.kotowicz.net/2014/01/xssing-with-shakespeare-name-calling.html", "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1403" ]
			}
		],
		"extractors" : {
			"uri"			: [ "/(?:easyXDM-)?([0-9][0-9.a-z_\-]+)/easyXDM(\.min)?\.js" ],
			"filename"		: [ "easyXDM-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ " \* easyXDM\n \* http://easyxdm.net/(?:\r|\n|.)+version:\"([0-9][0-9.a-z_\-]+)\"",
								"@class easyXDM(?:.|\r|\n)+@version ([0-9][0-9.a-z_\-]+)(\r|\n)" ],
			"hashes"		: { "cf266e3bc2da372c4f0d6b2bd87bcbaa24d5a643" : "2.4.6"}
		}
	},

	"plupload" : {
		"vulnerabilities" : [
			{
				"below" : "1.5.4",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2012-2401" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2012-2401/" ]
			},
			{
				"below" : "1.5.5",
				"severity": "high",
				"identifiers": {"CVE": [ "CVE-2013-0237" ] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2013-0237/" ]
			}
		],
		"extractors" : {
			"func"			: [ "plupload.VERSION" ],
			"uri"			: [ "/([0-9][0-9.a-z_\-]+)/plupload(\.min)?\.js" ],
			"filename"		: [ "plupload-([0-9][0-9.a-z_\-]+)(.min)?\.js" ],
			"filecontent"	: [ "\* Plupload - multi-runtime File Uploader(?:\r|\n)+ \* v([0-9][0-9.a-z_\-]+)",
								"var g=\{VERSION:\"([0-9][0-9.a-z_\-]+)\",.*;window.plupload=g\}"
								],
			"hashes"		: {}
		}
	},

	"DOMPurify" : {
		"vulnerabilities" : [
			{
				"below" : "0.6.1",
				"severity": "medium",
				"identifiers": { },
				"info" : [ "https://github.com/cure53/DOMPurify/releases/tag/0.6.1" ]
			}
		],
		"extractors" : {
			"func"			: [ "DOMPurify.version" ],
			"filecontent"	: [ "DOMPurify.version = '([0-9][0-9.a-z_\-]+)';" ],
			"hashes"		: {}
		}
	},

	"flowplayer" : {
		"vulnerabilities" : [
			{
				"below" : "5.4.3",
				"severity": "medium",
				"identifiers": { "summary" : "XSS vulnerability in Flash fallback" },
				"info" : [ "https://github.com/flowplayer/flowplayer/issues/381" ]
			}
		],
		"extractors" : {
			"uri"			    : [ "flowplayer-([0-9][0-9.a-z_\-]+)(\.min)?\.js" ],
			"filename"		: [ "flowplayer-([0-9][0-9.a-z_\-]+)(\.min)?\.js" ]
		}
	},

	"DWR" : {
		"vulnerabilities" : [
			{
				"below" : "1.1.4",
				"severity": "high",
				"identifiers": { "CVE" : "CVE-2007-01-09" },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2014-5326/", "http://www.cvedetails.com/cve/CVE-2014-5326/" ]
			},
			{
				"below" : "2.0.11",
				"severity": "medium",
				"identifiers": { "CVE" : ["CVE-2014-5326", "CVE-2014-5325"] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2014-5326/", "http://www.cvedetails.com/cve/CVE-2014-5326/" ]
			},
			{
				"above" : "3",
				"below" : "3.0.RC3",
				"severity": "medium",
				"identifiers": { "CVE" : ["CVE-2014-5326", "CVE-2014-5325"] },
				"info" : [ "http://www.cvedetails.com/cve/CVE-2014-5326/", "http://www.cvedetails.com/cve/CVE-2014-5326/" ]
			}
		],
		"extractors" : {
			"func"			: [ "dwr.version" ],
			"filecontent"	: [
				" dwr-([0-9][0-9.a-z_\-]+).jar"
			]
		}
	},

	"moment.js" : {
		"vulnerabilities" : [
			{
				"below" : "2.11.2",
				"severity": "low",
				"identifiers": { "summary":"reDOS - regular expression denial of service" },
				"info" : [ "https://github.com/moment/moment/issues/2936" ]
			}
		],
		"extractors" : {
			"func"			: [ "moment.version" ],
			"filecontent"	: [ "//! moment.js(?:[\n\r]+)//! version : ([0-9][0-9.a-z_\-]+)" ]
		}
	},

	"dont check" : {
		"extractors" : {
			"uri" : [
				"^http[s]?://(ssl|www).google-analytics.com/ga.js",
				"^http[s]?://apis.google.com/js/plusone.js",
				"^http[s]?://cdn.cxense.com/cx.js"
			]
		}
	}
}