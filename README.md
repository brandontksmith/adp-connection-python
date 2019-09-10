# ADP Client Connection Library for Python

The ADP Client Connection Library is intended to simplify and aid the process of authenticating, authorizing and connecting to the ADP Marketplace API Gateway. The Library includes a sample application that can be run out-of-the-box to connect to the ADP Marketplace API **test** gateway.

There are two ways of installing and using this library:

  - Clone the repo from Github: This allows you to access the raw source code of the library as well as provides the ability to run the sample application and view the Library documentation
  - Install from PyPI: When you are ready to use the library in your own application use this method to install it using pip

### Version
1.0.1

### Installation

**Clone from Github**

You can either use the links on Github or the command line git instructions below to clone the repo.

```sh
$ git clone https://github.com/adplabs/adp-connection-python.git adp-connection-python
```

followed by

```sh
$ cd adp-connection-python
$ make setup
$ make docs
```

The make setup will also install the **requests** package along with a few other developer dependencies. The make docs will generate the docs and open up a browser displaying the main docs page. If you run into errors you may need to run the setup using sudo.

```sh
$ sudo make setup
$ make docs
```

*Run the sample app*

```sh
$ cd adp_connection/democlient
$ python -u sampleApp.py
```

This starts an HTTP server on port 8889 (this port must be unused to run the sample application). You can point your browser to http://localhost:8889. The sample app allows you to connect to the ADP test API Gateway using the **client_credentials** and **authorization_code** grant types. For the **authorization_code** connection, you will be asked to provide an ADP username (MKPLDEMO) and password (marketplace1).

***

**Install from PyPI**

Make sure you have **pip** installed. Then use the following commad to install the library.

```sh
$ pip install adp_connection
```

If you run into errors, you may need to install using sudo.

```sh
$ sudo pip install adp_connection
```

You should now be able to import adp_connection in your own applications.

***

## Examples
### Create Client Credentials ADP Connection

```python
import sys
from os import curdir, sep
from adp_connection.lib import *

config = dict({})
config['clientID'] = '88a73992-07f2-4714-ab4b-de782acd9c4d'
config['clientSecret'] = 'a130adb7-aa51-49ac-9d02-0d4036b63541'
config['sslCertPath'] = 'certs/cert.pem'
config['sslKeyPath'] = 'certs/cert.key'
config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
config['apiRequestURL'] = 'https://iat-api.adp.com'
config['grantType'] = 'client_credentials'

# Initialize the Connection Configuration Object.
# Since the grant type is client_credentials a
# ClientCredentialsConfiguration object is returned
try:
    ClientCredentialsConfiguration = ConnectionConfiguration().init(config)

    # Using the new configuration object create a connection
    ccConnection = ADPAPIConnectionFactory().createConnection(ClientCredentialsConfiguration)

    resp = ''

    # try to connect and send the response back
    ccConnection.connect()
    if (ccConnection.isConnectedIndicator()):

        # A successful connection generates a UUID as a session identifier
        # which can be retrieved using the getSessionState() method call on
        # the connection. There is also provision to set a user-defined
        # session identifier using the setSessionState(string) method call on
        # the connection. This should be done after a connection has been
        # obtained from the connection factory, but before calling connect()
        #
        # We can use the session identifier as a key to store the connection
        # into the global connection dictionary for later retrieval on
        # subsequent requests
        self.connectionDict[ccConnection.getSessionState()] = ccConnection
        print 'Connected!'
        print 'access token: ' + ccConnection.getAccessToken()
        print 'expiration: ' + ccConnection.getExpiration().strftime("%Y-%m-%d %H:%M:%S")
        print 'session state:' + ccConnection.getSessionState()
    else:
        resp = '<b>Not Connected!</b>'
except ConfigError as conferr:
    print confErr.code + ': ' + conferr.msg
except ConnectError as connecterr:
    print connecterr.code + ': ' + connecterr.msg
except:
    print "Unexpected error:", str(sys.exc_info())
```

### Create Authorization Code ADP Connection

```python
import sys
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import urlparse, parse_qs
from os import curdir, sep
from adp_connection.lib import *

# This class will handles any incoming request from the browser


class httpHandler(BaseHTTPRequestHandler):
    """ Base class for handling HTTP Requests.
    Extends BaseHTTPRequestHandler """

    # Global connections dictionary
    connectionDict = dict({})

    # Handler for the GET requests
    def do_GET(self):
        """ Handle GET Requests """

        parsed_url = urlparse(self.path)
        real_path = parsed_url.path
        query = parsed_url.query
        query_components = parse_qs(query)

        try:
            # Handle request for an Authorization Code App
            if self.path == '/authorization_code':
                config = dict({})
                config['clientID'] = 'ec762f06-7410-4f6d-aa82-969902c1836a'
                config['clientSecret'] = '6daf2cd7-4604-46c0-ab43-a645a6571d34'
                config['sslCertPath'] = 'certs/cert.pem'
                config['sslKeyPath'] = 'certs/cert.key'
                config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
                config['apiRequestURL'] = 'https://iat-api.adp.com'
                config['grantType'] = 'authorization_code'
                config['baseAuthorizationURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/authorize'
                config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
                config['redirectURL'] = 'http://localhost:8889/callback'
                config['responseType'] = 'code'
                config['scope'] = 'openid'

                # Initialize the Connection Configuration Object.
                # Since the grant type is client_credentials an
                # AuthorizationCodeConfiguration object is returned
                try:
                    AuthorizationCodeConfiguration = ConnectionConfiguration().init(config)

                    # Using the new configuration object create a connection
                    acConnection = ADPAPIConnectionFactory().createConnection(AuthorizationCodeConfiguration)

                    # Authorization Code Apps require a user to login to ADP
                    # So obtain the authorization URL to redirect the user's
                    # browser to so that they can login
                    authURL = acConnection.getAuthorizationURL()

                    # The url returned by the getAuthorizationURL() method contains a 'state'
                    # query parameter. This is a session identifier that can be used in later
                    # requests to maintainconnection and session information.
                    # The session identifier can also be set to a user-defined value by calling
                    # the setSessionState() method on the connection right after the connection
                    # is created
                    state = parse_qs(urlparse(authURL).query)['state'][0]

                    # Here we set the session identifier to the value provided by the
                    # call to the getAuthroizationURL() method of the connection
                    acConnection.setSessionState(state)

                    # Store the connection object in the global connections dictionary using
                    # 'state' as the key
                    self.connectionDict[state] = acConnection

                    # Send the 302 temporary redirect response to the browser
                    self.send_response(302)
                    self.send_header("Location", authURL)
                    self.end_headers()
                    return
                except ConfigError as conferr:
                    print conferr.msg
                    raise
                except ConnectError as connecterr:
                    print connecterr.msg
                    raise

            # Handle the callback request after a login attempt for an
            # Authorization Code App. The path being checked must be
            # the same as that was registered for the App with ADP and
            # specified during the initialzation of the connection config object
            elif real_path == '/callback':

                # A successful login returns an Authorization Code in the 'code'
                # query parameter
                try:
                    code = query_components['code'][0]
                except KeyError:
                    code = ''
                if (code == ''):
                    self.send_error(401, 'Unauthorized')
                    return
                resp = ''

                # The 'state' query parameter that as sent as part of the 302
                # redirect url is returned back. Use this to find the connection
                # from the global connection dictionary
                try:
                    state = query_components['state'][0]
                    acConnection = self.connectionDict[state]
                except KeyError:
                    # Send the 302 temporary redirect response to the browser
                    self.send_response(302)
                    self.send_header("Location", '/authorization_code')
                    self.end_headers()
                    return
                # Save the authorization code in the connection config
                acConnection.getConfig().setAuthorizationCode(code)

                # try to connect and handle exceptions
                # and send the response back
                try:
                    acConnection.connect()
                    if (acConnection.isConnectedIndicator()):
                        self.connectionDict[state] = acConnection
                        resp = '<b>Connected!</b>'
                        resp = resp + '<br>access token: ' + acConnection.getAccessToken()
                        resp = resp + '<br>expiration: ' + acConnection.getExpiration().strftime("%Y-%m-%d %H:%M:%S")
                        resp = resp + '<br>session state:' + acConnection.getSessionState()
                    else:
                        resp = '<b>Not Connected!</b>'
                except ConnectError as connecterr:
                    resp = '<b>Connection Error</b>'
                    resp = resp + '<br>Error Code: ' + connecterr.code
                    resp = resp + '<br>Error Message: ' + connecterr.msg
                    resp = resp + '<br>API Class: ' + connecterr.cname
                except:
                    print "Unexpected error:", str(sys.exc_info())
                finally:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(resp)
                    return
            else:
                raise IOError
        except IOError:
            self.send_error(404, 'File Not Found: %s' % self.path)
```

## API Documentation ##

Documentation on the individual API calls provided by the library is automatically generated from the library code. To generate the documentation, please complete the following steps:

```
make docs
```

The generated documentation can be viewed by opening adp_connection/docs/_build/html/index.html in your browser.

## Tests ##

Automated unit tests are available in tests folder. To run the tests, please complete the following steps.

```
make test
```

The above will also display code coverage information. To generate an html version of the code coverage report, please complete the following steps.

```
make coverage-html
```

The resulting report can be viewed by opening htmlcov/index.html in your browser.

## Dependencies ##

This library has the following **install** dependencies. These are installed automatically as part of the 'make setup' or 'pip install adp-connection' if they don't exist.

* requests

This library has the following **development/test** dependencies. These are installed automatically as part of the 'make setup' if they don't exist.

* mock
* nose
* coverage
* yanc
* preggy
* coveralls
* sphinx
 
## Contributing ##

To contribute to the library, please generate a pull request. Before generating the pull request, please insure the following:

1. Appropriate unit tests have been updated or created.
2. Code coverage on the unit tests must be no less than 95%.
3. Your code updates have been fully tested.
4. Update README.md and API documentation as appropriate.
 
## License ##

This library is available under the Apache 2 license (http://www.apache.org/licenses/LICENSE-2.0).
