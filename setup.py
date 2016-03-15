from distutils.core import setup
setup(
  name = 'retirejs',
  packages = ['retirejs'], # this must be the same as the name above
  version = '1.1',
  description = 'Port of RetireJS in Python',
  author = 'Fallible Inc',
  author_email = 'hello@fallible.co',
  url = 'https://github.com/FallibleInc/retirejslib', # use the URL to the github repo
  download_url = 'https://github.com/FallibleInc/retirejslib/tarball/1.1', 
  keywords = ['security', 'retirejs', 'python'], # arbitrary keywords
  classifiers = [],
  install_requires=[
          'requests',
      ],
)
