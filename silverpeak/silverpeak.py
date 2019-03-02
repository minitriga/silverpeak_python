import requests
from . exceptions import LoginCredentialsError, LoginTimeoutError
from collections import namedtuple
from requests.exceptions import ConnectionError

HTTP_SUCCESS_CODES = {
    200: 'Success',
}

HTTP_ERROR_CODES = {
    400: 'Bad Request',
    403: 'Forbidden',
    404: 'API Not found',
    406: 'Not Acceptable Response',
    415: 'Unsupported Media Type',
    500: 'Internal Server Error'
}

HTTP_RESPONSE_CODES = dict()
HTTP_RESPONSE_CODES.update(HTTP_SUCCESS_CODES)
HTTP_RESPONSE_CODES.update(HTTP_ERROR_CODES)

# parse_response will return a namedtuple object
Result = namedtuple('Result', [
    'ok', 'status_code', 'error', 'reason', 'data', 'response'
])
 
def parse_http_success(response):
    """
    HTTP 2XX responses
    :param response: requests response object
    :return: namedtuple result object
    """
    if response.request.method in ['GET']:
        reason = HTTP_RESPONSE_CODES[response.status_code]
        error = ''
        if response.json():
            json_response = response.json()
        else:
            json_response = dict()
            reason = HTTP_RESPONSE_CODES[response.status_code]
            error = 'No data received from device'
    else:
        json_response = dict()
        reason = HTTP_RESPONSE_CODES[response.status_code]
        error = ''

    result = Result(
        ok=response.ok,
        status_code=response.status_code,
        reason=reason,
        error=error,
        data=json_response,
        response=response,
    )
    return result

def parse_http_error(response):
    """
    HTTP 4XX and 5XX responses
    :param response: requests response object
    :return: namedtuple result object
    """
    try:
        json_response = dict()
        reason = response.json()['error']['details']
        error = response.json()['error']['message']
    except ValueError as e:
        json_response = dict()
        reason = HTTP_RESPONSE_CODES[response.status_code]
        error = e

    result = Result(
        ok=response.ok,
        status_code=response.status_code,
        reason=reason,
        error=error,
        data=json_response,
        response=response,
    )
    return result

def parse_response(response):
    """
    Parse a request response object
    :param response: requests response object
    :return: namedtuple result object
    """
    if response.status_code in HTTP_SUCCESS_CODES:
        return parse_http_success(response)

    elif response.status_code in HTTP_ERROR_CODES:
        return parse_http_error(response)


class Silverpeak(object):
    def __init__(self, user, user_pass, sp_server, sp_port="443", verify=False, disable_warnings=False, timeout=10, auto_login=True):
        self.user = user
        self.user_pass = user_pass
        self.sp_server = sp_server
        self.sp_port = sp_port
        self.timeout = timeout
        self.auto_login = auto_login
        self.verify = verify
        self.disable_warnings = disable_warnings

        if self.disable_warnings:
             requests.packages.urllib3.disable_warnings()

        self.base_url = 'https://{0}:{1}/gms/rest'.format(
            self.sp_server,
            self.sp_port
        )

        self.session = requests.session()
        
        if not self.verify:
            self.session.verify = self.verify
     
        if self.auto_login:
            self.login_result = self.login()

    def login(self):

        requestData = {
            "user": self.user, "password": self.user_pass 
        }

        try:
            login_result = self._post(
                session=self.session,
                url='{0}/authentication/login'.format(self.base_url),
                headers={'Content-Type': 'application/json'},
                json=requestData,
                timeout=self.timeout
            )
        except ConnectionError:
            raise LoginTimeoutError('Could not connect to {0}'.format(self.sp_server))
        
        if login_result.response.text.startswith('wrong credentials'):
            raise LoginCredentialsError('Could not login to device, check user credentials')

        else:
            return login_result

    @staticmethod
    def _get(session, url, headers=None, timeout=10):
        """
        Perform a HTTP get
        :param session: requests session
        :param url: url to get
        :param headers: HTTP headers
        :param timeout: Timeout for request response
        :return:
        """
        if headers is None:
            headers = {'Connection': 'keep-alive', 'Content-Type': 'application/json'}

        return parse_response(session.get(url=url, headers=headers, timeout=timeout))
    
    @staticmethod
    def _post(session, url, headers=None, data=None, json=None, timeout=10):
        """
        Perform a HTTP post
        :param session: requests session
        :param url: url to post
        :param headers: HTTP headers
        :param data: Data payload
        :param timeout: Timeout for request response
        :return:
        """
        if headers is None:
            # add default headers for post
            headers = {'Connection': 'keep-alive', 'Content-Type': 'application/json'}

        if data is None:
            data = dict()

        if json is None:
            json = dict()

        return parse_response(session.post(url=url, headers=headers, data=data, json=json, timeout=timeout))
    



    def get_appliances(self):
        url = '{0}/appliance'.format(self.base_url)
        return self._get(self.session, url)
