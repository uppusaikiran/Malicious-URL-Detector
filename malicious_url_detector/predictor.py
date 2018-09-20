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
import sys
import logging
from app import URL_H


__author__ = "uppusaikiran"
__copyright__ = "uppusaikiran"
__license__ = "none"

_logger = logging.getLogger('url-predictor')
_logger.setLevel(logging.INFO)
fh = logging.FileHandler('url.log')
fh.setLevel(logging.INFO)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)
# add the handlers to logger
_logger.addHandler(ch)
_logger.addHandler(fh)

def fib(n):
    """
    Fibonacci example function

    :param n: integer
    :return: n-th Fibonacci number
    """
    assert n > 0
    a, b = 1, 1
    for i in range(n-1):
        a, b = b, a+b
    return a

def result(url_passed):
    """
    Malicious URL function
    
    :param url_passed: url
    :return: clean/malicious
    """
    url = URL_H()
    try:
        os.path.exists(os.path.join(os.path.dirname(os.path.realpath(__file__)),'url.pickle'))
        pickle_in = open(PICKLE_FILE,'rb')
        clf = pickle.load(pickle_in)
        url.suspicious_indicators()
        result = url.test(url_passed)
    except Exception as e:
        _logger.warning('MODEL FILE IS NOT GENERATOR.. Will be generated for one time')
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
    #logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
