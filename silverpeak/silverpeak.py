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
        reason = HTTP_RESPONSE_CODES[response.status_code]
        error = ''
        if response.text:
            json_response = response.text
        else:
            json_response = dict()

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

        self.base_url = 'https://{}:{}/gms/rest'.format(
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
                url='{}/authentication/login'.format(self.base_url),
                headers={'Content-Type': 'application/json'},
                json=requestData,
                timeout=self.timeout
            )
        except ConnectionError:
            raise LoginTimeoutError(
                'Could not connect to {}'.format(self.sp_server))

        if login_result.response.text.startswith('wrong credentials'):
            raise LoginCredentialsError(
                'Could not login to device, check user credentials')

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
            headers = {'Connection': 'keep-alive',
                       'Content-Type': 'application/json'}

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
            headers = {'Connection': 'keep-alive',
                       'Content-Type': 'application/json'}

        if data is None:
            data = dict()

        if json is None:
            json = dict()

        return parse_response(session.post(url=url, headers=headers, data=data, json=json, timeout=timeout))

    def get_appliances(self):
        """
        Get all appliance information
        :return: Result named tuple.
        """
        url = '{}/appliance'.format(self.base_url)
        return self._get(self.session, url)

    def get_appliance(self, applianceID):
        """
        Get device information for one Appliance
        :param applianceID: Device Primary Key for Appliance
        :return: Result named tuple.
        """
        url = '{}/appliance/{}'.format(self.base_url, applianceID)
        return self._get(self.session, url)

    def get_reach_app(self, applianceID):
        """
        Get the reachability status from the appliance
        :param applianceID: Device Primary Key for Appliance
        :return: Result named tuple.
        """
        url = '{}/reachability/appliance/{}'.format(self.base_url, applianceID)
        return self._get(self.session, url)

    def get_reach_gms(self, applianceID):
        """
        Get the reachability status from the orchestrator
        :param applianceID: Device Primary Key for Appliance
        :return: Result named tuple.
        """
        url = '{}/reachability/gms/{}'.format(self.base_url, applianceID)
        return self._get(self.session, url)

    def get_groups(self):
        """
        Get all orchestrator groups
        :return: Result named tuple.
        """
        url = '{}/gms/group'.format(self.base_url)
        return self._get(self.session, url)

    def get_group(self, groupID):
        """
        Get a sigle group from orchestrator
        :param groupID: Group Primary Key looks like 10.Network
        :return: Result named tuple.
        """
        url = '{}/gms/group/{}'.format(self.base_url, groupID)
        return self._get(self.session, url)

    def get_group_root(self):
        """
        Get root group
        :return: Result named tuple.
        """
        url = '{}/gms/group/root'.format(self.base_url)
        return self._get(self.session, url)

    def get_grnodes(self):
        """
        Get appliance positions on a map for topology
        :return: Result named tuple.
        """
        url = '{}/gms/grNode'.format(self.base_url)
        return self._get(self.session, url)

    def get_grnode(self, nodeID):
        """
        Get appliance position by graphical node primary key
        :param nodeID: Node Primary Key looks like 0.GrNode
        :return: Result named tuple.
        """
        url = '{}/gms/grNode/{}'.format(self.base_url, nodeID)
        return self._get(self.session, url)

    def get_discovered(self):
        """
        Reurns all the discovered appliances
        :return: Result named tuple
        """
        url = '{}/appliance/discovered'.format(self.base_url)
        return self._get(self.session, url)

    def get_approved(self):
        """
        Reurns all approved appliances
        :return: Result named tuple
        """
        url = '{}/appliance/approved'.format(self.base_url)
        return self._get(self.session, url)

    def get_denied(self):
        """
        Reurns all the denied appliances
        :return: Result named tuple
        """
        url = '{}/appliance/denied'.format(self.base_url)
        return self._get(self.session, url)

    def get_interfaces(self, applianceID, cashed='true'):
        """
        Reurns node configuration data from orchestrator database or from the specified appliance
        :param applianceID: The node ID of the appliance
        :param cashed: True/false Get from orchestrator/get from appliance
        :return: Result named tuple
        """
        url = '{}/interfaceState/{}?cached={}'.format(
            self.base_url, applianceID, cashed.lower())
        return self._get(self.session, url)

    def get_device_alarms(self, applianceID, view='all', severity='', order='', maxAlarms=5):
        """
        Reurns active, historical, or all alarms for appliances whos id's are provided in the request body
        :param applianceID: The node ID of the appliance
        :param view: Filters arams by active, closed, all
        :param severity: Filters alarms by severity (warning, minor, major, critical)
        :param order: Order by alarm severity (true, false)
        :param maxAlarms: How many alarms to show (default=5)
        :return: Result named tuple
        """
        url = '{}/alarm/appliance?view={}&maxAlarms={}'.format(
            self.base_url, view.lower(), maxAlarms)

        if severity:
            url = '{}&severity={}'.format(url, severity)

        if order:
             url = '{}&order={}'.format(url, order)

        return self._post(
                session=self.session,
                url=url,
                headers={'Content-Type': 'application/json'},
                json=applianceID,
                timeout=self.timeout
               )

    def get_alarms(self, view='all', severity=''):
        """
        Reurns active, historical, or all alarms for appliances whos id's are provided in the request body
        :param view: Filters arams by active, closed, all
        :param severity: Filters alarms by severity (warning, minor, major, critical)
        :return: Result named tuple
        """
        url = '{}/alarm/gms?view={}'.format(self.base_url, view.lower())

        if severity:
            url = '{}&severity={}'.format(url, severity)

        return self._get(self.session, url)
   
    def get_alarm_summary(self):
        """
        Returns summary of active Orchestrator alarms as well as summary of active alarms across all appliances
        :return: Result named tuple
        """
        url = '{}/alarm/summary'.format(self.base_url)

        return self._get(self.session, url)

    def get_alarm_summary_type(self, alarmType):
        """
        Returns summary of active Orchestrator alarms or summary of active alarms across all appliances
        :param alarmType: Alarm Type (gms,appliance)
        :return: Result named tuple
        """
        url = '{}/alarm/summary/{}'.format(self.base_url, alarmType)

        return self._get(self.session, url)

    def post_preconfig(self, name, serialNum, tag, comment, configData, autoApply=None):
        """
        Create a preconfiguration
        :param name: name of the preconfig
        :param serialNum: Serial Number of the EC
        :param tag: Tag of the EC
        :param comment: Comment of the preconfig
        :param autoApply: True/false automatically approve EC when discovered
        :param configData: YAML file containing variables
        """
        try:
            import base64
            import json
        except ImportError:
            raise ImportError('Failed to import module')

        if autoApply is None:
            autoApply = True

        base64_bytes = base64.b64encode(configData)

        encodedConfig = base64_bytes.decode('utf-8')

        preConfig = { "name": name, "serialNum": serialNum, "tag": tag, "comment": comment, "autoApply": autoApply, "configData": encodedConfig }

        preConfig = json.dumps(preConfig)

        url = '{}/gms/appliance/preconfiguration'.format(self.base_url)

        return self._post(
                session=self.session,
                url=url,
                headers={'Content-Type': 'application/json'},
                data=preConfig,
                timeout=self.timeout
               )

    def reboot_appliance(self, applianceID, factoryReset=None):
        """
        Reboot appliance with or without factory reset
        :param applianceID: The node ID of the appliance
        :param factoryReset: Factory reset True False
        :return: Result named tuple
        """
        url = '{}/appliance/rest/{}/reboot'.format(self.base_url, applianceID)

        if factoryReset is None:
            data = '{"reboot_type":"Normal","save_db":true,"clear_nm":false,"next_partition":false,"empty_db":false,"empty_db_err":false,"delay":0}'
        else:
            data = '{"reboot_type":"Normal","save_db":true,"clear_nm":false,"next_partition":false,"empty_db":false,"empty_db_err":false,"delay":0,"reset_factory":true,"support_bypass":false}'

        return self._post(
                session=self.session,
                url=url,
                headers={'Content-Type': 'application/json'},
                data=data,
                timeout=self.timeout
                )

    def boost_appliance(self, applianceID, plus=False, boost=False, boostBandwidth=0):
        """
        Configure Boost on an appliance
        :param applianceID: The node ID of the appliance
        :param mini: enable or disable the mini licence
        :param plus: enable or disable the plus licence
        :param boost: enable or disable the boost licence
        :param boostBandwidth: choose bandwidth to boost by
        """
        try:
            import json
        except ImportError:
            raise ImportError('Failed to import module')

        url = '{}/license/portal/ec/{}'.format(self.base_url, applianceID)

        boostBandwidth = int(boostBandwidth)

        data = {
                "license": {
                   "plus": {
                      "enable": plus
                   },
                   "boost": {
                      "enable": boost,
                      "bandwidth": boostBandwidth
                   }
                }
               }

        data = json.dumps(data)

        return self._post(
                session=self.session,
                url=url,
                headers={'Content-Type': 'application/json'},
                data=data,
                timeout=self.timeout
                )
