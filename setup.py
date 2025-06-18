#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Setup file
#
import glob
import os
import platform

from setuptools import setup, find_packages
from subprocess import *

PACKAGE_NAME = "impacket-plus"

VER_MAJOR = 0
VER_MINOR = 1
VER_MAINT = 0
VER_PREREL = "stable"
try:
    if call(["git", "branch"], stderr=STDOUT, stdout=open(os.devnull, 'w')) == 0:
        p = Popen("git log -1 --format=%cd --date=format:%Y%m%d.%H%M%S", shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
        (outstr, __) = p.communicate()
        (VER_CDATE,VER_CTIME) = outstr.strip().decode("utf-8").split('.')

        p = Popen("git rev-parse --short HEAD", shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
        (outstr, __) = p.communicate()
        VER_CHASH = outstr.strip().decode("utf-8")

        VER_LOCAL = "+{}.{}.{}".format(VER_CDATE, VER_CTIME, VER_CHASH)
    else:
        VER_LOCAL = ""
except Exception:
    VER_LOCAL = ""

if platform.system() != 'Darwin':
    data_files = [(os.path.join('share', 'doc', PACKAGE_NAME), ['README.md', 'LICENSE']+glob.glob('doc/*'))]
else:
    data_files = []


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name=PACKAGE_NAME,
    version="{}.{}.{}".format (VER_MAJOR, VER_MINOR, VER_MAINT),
    # version="{}.{}.{}.{}{}".format(VER_MAJOR, VER_MINOR, VER_MAINT,VER_PREREL,VER_LOCAL),
    author="SecureAuth Corporation",
    maintainer="Fortra",
    license="Apache modified",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    platforms=["Unix", "Windows"],
    packages=find_packages(include=["impacket_plus", "impacket_plus.*"]),
    scripts=glob.glob(os.path.join('examples', '*.py')),
    data_files=data_files,

    install_requires=['impacket', 'tqdm'],
    extras_require={':sys_platform=="win32"': ['pyreadline3'],
                    },
    classifiers=[
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.8",

    ]
)
