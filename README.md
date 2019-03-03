# silverpeak_python
Python library for use with Silver Peak SD-WAN Orchestrator API.  
Requires [requests](http://docs.python-requests.org/en/master/)

### About
[Silver Peak](https://www.silver-peak.com/) is an SD-WAN vendor with a solid rest API. 
The API is documented on the orchestrator host and can be found by going to 
`https://hostname/orch_version/webclient/php/swagger/index.html`.

### Installation
```bash
pip install silverpeak
```

### Instantiate a connection to a vManage device
```python
from silverpeak import *
sp = Silverpeak(user='admin', user_pass='admin', sp_server='192.168.1.2')
```

### Call methods
```python
devices = sp.get_appliances()
```

### Returned Result
All methods return a Result named tuple with the `requests.json()` data in the `data` element.  
The complete `requests.response` object is stored in the `response` element
```python
Result(ok=True, status_code=200, error='', reason='Success', data={}, response=<Response [200]>)
```
