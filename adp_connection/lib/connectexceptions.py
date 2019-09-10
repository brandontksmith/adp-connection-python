#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of adp-api-client.
# https://github.com/adplabs/adp-connection-python

# Copyright © 2015-2016 ADP, LLC.

# Licensed under the Apache License, Version 2.0 (the “License”);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an “AS IS” BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.  See the License for the specific language
# governing permissions and limitations under the License.


class Error(Exception):
    """Base class for exceptions in this module.

    Attributes:
        cname -- class in which the error occurred
        code -- error code
        msg -- error message
    """

    errDict = dict({})
    errDict['clientID'] = {'errCode': 'ConfErr-001', 'errMsg': 'clientID not set'}
    errDict['clientSecret'] = {'errCode': 'ConfErr-002', 'errMsg': 'clientSecret not set'}
    errDict['sslCertPath'] = {'errCode': 'ConfErr-003', 'errMsg': 'sslCertPath not set'}
    errDict['sslKeyPath'] = {'errCode': 'ConfErr-004', 'errMsg': 'sslKeyPath not set'}
    errDict['tokenServerURL'] = {'errCode': 'ConfErr-005', 'errMsg': 'tokenServerURL not set'}
    errDict['apiRequestURL'] = {'errCode': 'ConfErr-006', 'errMsg': 'apiRequestURL not set'}
    errDict['disconnectURL'] = {'errCode': 'ConfErr-007', 'errMsg': 'disconnectURL not set'}
    errDict['grantType'] = {'errCode': 'ConfErr-008', 'errMsg': 'grantType not set'}
    errDict['baseAuthorizationURL'] = {'errCode': 'ConfErr-009', 'errMsg': 'baseAuthorizationURL not set'}
    errDict['redirectURL'] = {'errCode': 'ConfErr-010', 'errMsg': 'redirectURL not set'}
    errDict['responseType'] = {'errCode': 'ConfErr-011', 'errMsg': 'responseType not set'}
    errDict['scope'] = {'errCode': 'ConfErr-012', 'errMsg': 'scope not set'}
    errDict['grantTypeBad'] = {'errCode': 'ConfErr-013', 'errMsg': 'incorrect grant type'}
    errDict['responseTypeBad'] = {'errCode': 'ConfErr-013', 'errMsg': 'incorrect responseType'}
    errDict['scopeBad'] = {'errCode': 'ConfErr-013', 'errMsg': 'incorrect scope'}
    errDict['initBad'] = {'errCode': 'ConfErr-014', 'errMsg': 'configuration not inited'}

    def __init__(self, cname, code, msg):
        self.cname = cname
        self.msg = msg
        self.code = code


class ConnectError(Error):
    """Exception raised for errors in connecting to ADP. """


class ConfigError(Error):
    """Exception raised for errors in initializing the
    connection configuration. """
