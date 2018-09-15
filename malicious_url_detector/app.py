#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following line in the
entry_points section in setup.cfg:

    console_scripts =
        hello_world = malicious_url_detector.module:function

Then run `python setup.py install` which will install the command `hello_world`
inside your current environment.
Besides console scripts, the header (i.e. until _logger...) of this file can
also be used as template for Python modules.

Note: This skeleton file can be safely removed if not needed!
"""
from __future__ import division, print_function, absolute_import
import os
import sys
import re
import matplotlib
import pandas as pd
import numpy as np
import ipaddress as ip
import tldextract
import whois
import pickle
import argparse
import logging
import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import sklearn.ensemble as ek
from os.path import splitext
from datetime import datetime
from multiprocessing import Process,Pool,Lock
from sklearn import cross_validation, tree, linear_model
from sklearn.feature_selection import SelectFromModel
from sklearn.externals import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn import preprocessing
from sklearn import svm
from sklearn.linear_model import LogisticRegression
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


__author__ = "uppusaikiran"
__copyright__ = "uppusaikiran"
__license__ = "MIT"

_logger = logging.getLogger(__name__)


class URL_H:
    
    def __init__(self):
        self.sample_set_path     = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'final_training_set.csv')
        self.suspicious_tld_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'bad_tlds.csv')
        self.suspicious_domains  = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'suspicious_domain.csv')
        self.featureSet = pd.DataFrame(
                                    columns=(
                                        'url','no of dots','presence of hyphen','len of url','presence of at',\
                                        'presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP',\
                                        'presence of Suspicious_TLD','presence of suspicious domain','label'
                                        )
                                    )

    def preprocess(self):
        self.df = pd.read_csv(self.sample_set_path)
        self.df = self.df.sample(frac=1).reset_index(drop=True)
        print(self.df.head())

    def total_records(self):
        print(len(self.df))
   
    def suspicious_indicators(self):
        self.Suspicious_TLD = []
        self.Suspicious_Domain = []
        
        with open(self.suspicious_tld_path,'r') as f:
            for i in f:
                self.Suspicious_TLD.append(i.split('\n')[0])
        with open(self.suspicious_domains,'r') as f:
            for i in f:
                self.Suspicious_Domain.append(i.split('\n')[0])
    
    def countdots(self,url):
        return url.count('.')    

    def count_delimiters(self,url):
        count = 0
        common_delimters = [';','_','?','=','&','(',')',',','$','-','!','*']
        for each in url:
            if each in common_delimters:
                count +=1
        return count
    def check_ip(self,uri):
        try:
            if ip.ip_address(uri):
                return 1
        except:
                return 0

    def check_hypen(self,url):
        return url.count('-')
    
    def check_at(self,url):
        return url.count('@')
       
    def check_d_slash(self,url):
        return url.count('//')
       
    def check_sub_dir(self,url):
        return url.count('/')
    
    def check_extension(self,url):
        
        root , ext = splittext(url) 
        return ext

    def count_sub_domain(self,subdomain):
        if not subdomain:
            return 0
        else:
            return len(subdomain.split('.'))
   
    def count_queries(self,query):
        if not query:
            return 0
        else:  
            return len(query.split('&'))
    
    def length_url(self,url):
        return len(url)
    

    def length_domain_name(self,domain_name):
        return len(domain_name)    
        
    def no_of_queries(self,path):
        return len(path.query)
    
    def is_bad_tld(self,tld):
        if tld in self.Suspicious_TLD:
            return 1  
        else:
            return 0

    def is_bad_domain(self,domain):
        if domain in self.Suspicious_Domain:
            return 1
        else:
            return 0

   
    def extract_url_features(self,url,label):
        result = []
        self.url = str(url)
        
        result.append(self.url)
        self.path = urlparse(self.url)
        self.ext = tldextract.extract(self.url)
        result.append(self.countdots(self.ext.subdomain))
        result.append(self.check_hypen(self.path.netloc))
        result.append(self.length_url(self.url))
        result.append(self.check_at(self.path.netloc))
        result.append(self.check_d_slash(self.path.path))
        result.append(self.check_sub_dir(self.path.path))
        result.append(self.count_sub_domain(self.ext.subdomain))
        result.append(self.length_domain_name(self.path.netloc))
        result.append(self.no_of_queries(self.path))

        #Domain Information
        result.append(self.check_ip(self.ext.domain))
        
        #BAD TLD
        result.append(self.is_bad_tld(self.ext.suffix))
        result.append(self.is_bad_domain('.'.join(self.ext[1:])))
        result.append(str(label))
        print(result)
        return result
        
    @staticmethod
    def pp(self,i):
        try:
            print('Processing {}'.format(i))
            features = self.extract_url_features(self.df["URL"].loc[i], self.df["Lable"].loc[i])
            self.featureSet.loc[i] = features
            print('Processing Done {} -- features {}'.format(i,features))
        except Exception as e:
            print('Error in calculating features {}'.format(e))
    
    def start_scan(self,i):
        print('Processing {}'.format(i))
        features = self.extract_url_features(self.df["URL"].loc[i], self.df["Lable"].loc[i])
        self.featureSet.loc[i] = features
        print('Processing Done {} -- features {}'.format(i,features))

    def learn(self):
        #start = datetime.now()
        #pool = Pool(processes = 4) # number of processes
        #result = [pool.apply_async(self.pp,(i)) for i in range(len(self.df))]
        #pool.close()
        #pool.join()
        #results = [r.get()[0] for r in result]
        for i in range(len(self.df)):
            print('Processing {}'.format(i))
            features = self.extract_url_features(self.df["URL"].loc[i], self.df["Lable"].loc[i])
            self.featureSet.loc[i] = features
            print('Processing Done {} -- features {}'.format(i,features))

        print('Time taken',datetime.now()-start)
        print(self.featureSet.head())
        print(self.featureSet.groupby(self.featureSet['label']).size())
        X = self.featureSet.drop(['url','label'],axis=1).values
        y = self.featureSet['label'].values
        model = { 
             "RandomForest":ek.RandomForestClassifier(n_estimators=50,n_jobs=20)
        }
        X_train, X_test, y_train, y_test = cross_validation.train_test_split(X, y ,test_size=0.2)
        results = {}
        for algo in model:
            clf = model[algo]
            clf.fit(X_train,y_train)
            with open('url.pickle','wb') as f:
                pickle.dump(clf,f)
            score = clf.score(X_test,y_test)
            print(("%s : %s " %(algo, score)))
            results[algo] = score        

        winner = max(results, key=results.get)
        print(winner)
        self.clf = model[winner]
        res = self.clf.predict(X)
        mt = confusion_matrix(y, res)
        print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
        print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))

    def test(self,url):
        result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at',\
'presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','presence of Suspicious_TLD',\
'presence of suspicious domain','label'))

        results = self.extract_url_features(url, '1')
        result.loc[0] = results
        result = result.drop(['url','label'],axis=1).values
        print(self.clf.predict(result))
        return self.clf.predict(result).tolist()

def self_learn():
    url = URL_H()
    url.preprocess()
    url.suspicious_indicators()
    url.learn()

def main():
    url = URL_H()
    url.preprocess()
    url.suspicious_indicators()
    url.extract_url_features(sys.argv[1],0)
    url.learn()
    url.test(sys.argv[1])


if __name__ == '__main__':
    main() 
