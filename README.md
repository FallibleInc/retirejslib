### Port of [RetireJS](https://github.com/RetireJS/retire.js) in Python

#### Installation
`pip install retirejs`

#### How to use

```python
import retirejs

retirejs.scan_endpoint("http://code.jquery.com/jquery-1.6.min.js")


```


#### Sample Output:

```python
{'detection': 'filecontent', 'vulnerabilities': [{'info': ['http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-4969', 'http://research.insecurelabs.org/jquery/test/'], 'identifiers': {'CVE': ['CVE-2011-4969']}, 'severity': 'medium'}, {'info': ['http://bugs.jquery.com/ticket/11290', 'http://research.insecurelabs.org/jquery/test/'], 'identifiers': {'bug': '11290', 'summary': 'Selector interpreted as HTML'}, 'severity': 'medium'}, {'info': ['https://github.com/jquery/jquery/issues/2432', 'http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/'], 'identifiers': {'summary': '3rd party CORS request may execute'}, 'severity': 'medium'}], 'version': '1.6.0', 'component': 'jquery'}
```
