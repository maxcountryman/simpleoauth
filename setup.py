'''
    simpleoauth
    -----------

    A lightweight, generic, correct, OAuth 1.0/a, 2.0 signing library.

    Links
    `````
    * `documentation <https://simpleoauth.readthedocs.org/en/latest/>`_
    * `development version <https://github.com/maxcountryman/simpleoauth>`_
'''

import sys

from setuptools import setup, find_packages

about = {}
with open('simpleoauth/__about__.py') as f:
    exec(f.read(), about)

install_requires =[]
if sys.version_info[0] == 2:
    install_requires.append('ordereddict==1.1')

classifiers = ['Development Status :: 5 - Production/Stable',
               'Intended Audience :: Developers',
               'Programming Language :: Python',
               'License :: OSI Approved :: MIT License',
               'Natural Language :: English',
               'Operating System :: OS Independent',
               'Operating System :: MacOS',
               'Operating System :: POSIX',
               'Operating System :: POSIX :: Linux',
               'Programming Language :: Python',
               'Programming Language :: Python :: 2.6',
               'Programming Language :: Python :: 2.7',
               'Programming Language :: Python :: 3.3',
               'Programming Language :: Python :: Implementation',
               'Programming Language :: Python :: Implementation :: CPython',
               'Topic :: Internet :: WWW/HTTP',
               'Topic :: Software Development :: Libraries :: Python Modules',
               'Topic :: Utilities']

setup(name=about['__title__'],
      version=about['__version__'],
      description='An incredibly simple, generic OAuth library',
      author=about['__author__'],
      author_email='maxc@me.com',
      url='https://github.com/maxcountryman/simpleoauth',
      packages=find_packages(),
      install_requires=install_requires,
      license='MIT',
      keywords='oauth oauth1 oauth2',
      classifiers=classifiers,
    zip_safe=False)
