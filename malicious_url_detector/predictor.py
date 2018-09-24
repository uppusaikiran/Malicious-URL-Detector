#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following line in the
entry_points section in setup.cfg:

    console_scripts =
        hello_world = email_finder.module:function

Then run `python setup.py install` which will install the command `hello_world`
inside your current environment.
Besides console scripts, the header (i.e. until _logger...) of this file can
also be used as template for Python modules.

Note: This skeleton file can be safely removed if not needed!
"""
from __future__ import division, print_function, absolute_import

import argparse
import os
import pickle
import sys
import logging
import warnings
from app import URL_H
warnings.filterwarnings("ignore")

__author__ = "uppusaikiran"
__copyright__ = "uppusaikiran"
__license__ = "none"

_logger = logging.getLogger('url-predictor')
_logger.setLevel(logging.INFO)
fh = logging.FileHandler('url.log')
fh.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
_logger.addHandler(fh)


def result(url_passed):
    """
    Malicious URL function
    
    :param url_passed: url
    :return: clean/malicious
    """
    try:
        if os.path.exists(os.path.join(os.path.dirname(os.path.realpath(__file__)),'url.pickle')):
            _logger.info('Pickle file exists')
        pickle_in = open('url.pickle','rb')
        clf = pickle.load(pickle_in)
        url = URL_H()
        url.suspicious_indicators()
        result = url.test(url_passed)
        final = clf.predict(result)
    except Exception as e:
        _logger.warning('MODEL FILE IS NOT GENERATOR.. Will be generated for one time')
        _logger.error(e)
        print('Model file is not generated.So Building Model for one time')
        url = URL_H()
        url.preprocess()
        url.suspicious_indicators()
        url.learn()
        result(url_passed)
    return clf.predict(result)

def parse_args(args):
    """
    Parse command line parameters

    :param args: command line parameters as list of strings
    :return: command line parameters as :obj:`airgparse.Namespace`
    """
    parser = argparse.ArgumentParser(
        description="Just a Malicious URL detector")
    parser.add_argument(
        dest="url",
        help="Malicious URL input"
        )
    return parser.parse_args(args)


def main(args):
    args = parse_args(args)
    print("URL {} is {}".format(args.url, result(args.url)))
    _logger.info("Script ends here")


def run():
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
