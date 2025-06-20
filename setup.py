from setuptools import setup
import glob
import os

setup(
    scripts=glob.glob(os.path.join('examples', '*.py')),
)