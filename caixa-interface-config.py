import json

import sys

import requests

import time

import re



# disable the cert warnings since we're using the SSL off version of the REST calls

requests.packages.urllib3.disable_warnings()



# installations required

#  sudo apt-get -y install python2.7

#  sudo apt-get -y install python-requests

#  to run:

#      python2.7 exercise3.py apiuser mypassword 1





print("Configuring Interface IPs and NAT")



# this is the FMC local IP in all pods

server = "https://198.18.128.180"


ngfwvInsideZoneId  = ""

ngfwvOutsideZoneId = ""



ngfwv01Name         = "FTD-FW3"

ngfwv01Id           = ""

ngfwv01InsideIP     = "10.1.0.1"

ngfwv01InsideMask   = "24"




#=========================================================================

# Define a few helpful functions

#=========================================================================

# REST get

def RESTget(url):

    """Issue RESTget and update resp and json_resp

       This function will update: 

          resp: The complete response from the call

          json_resp: The python dict version of the data

    """

    global resp, json_resp

    time.sleep(1)

    try:

        # REST call with SSL verification turned off: 

        r = requests.get(url, headers=headers, verify=False)

        # REST call with SSL verification turned on:

        # r = requests.get(url, headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code

        resp = r.text

        if (status_code == 200):

            print("GET successful. Response data --> ")

            json_resp = json.loads(resp)

            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))

        else:

            r.raise_for_status()

            print("Error occurred in GET --> "+resp)

            raise Exception("Error occured in Get -->"+resp)

    except requests.exceptions.HTTPError as err:

        print ("Error in connection --> "+str(err))

        raise Exception("Error in connection --> "+str(err))

    finally:

        if r : r.close()



# REST post

def RESTpost(url,post_data):

    """Issue RESTpost and update resp and json_resp

       This function will update: 

          resp: The complete response from the call

          json_resp: The python dict version of the data

       """

    global resp, json_resp

    time.sleep(1)

    try:

        # REST call with SSL verification turned off:

        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)

        # REST call with SSL verification turned on:

        #r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code

        resp = r.text

        print("Status code is: "+str(status_code))

        if status_code == 201 or status_code == 202:

            print ("Post was successful...")

            json_resp = json.loads(resp)

            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))

        else :

            r.raise_for_status()

            print ("Error occurred in POST --> "+resp)

    except requests.exceptions.HTTPError as err:

        print ("Error in connection --> "+str(err))

    finally:

        if r: r.close()



# REST put

def RESTput(url,put_data):

    """Issue RESTput and update resp and json_resp

       This function will update: 

          resp: The complete response from the call

          json_resp: The python dict version of the data

       """

    global resp, json_resp

    time.sleep(1)

    try:

        # REST call with SSL verification turned off:

        r = requests.put(url, data=json.dumps(put_data), headers=headers, verify=False)

        # REST call with SSL verification turned on:

        # r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')

        status_code = r.status_code

        resp = r.text

        if (status_code == 200):

            print("Put was successful...")

            json_resp = json.loads(resp)

            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))

        else:

            r.raise_for_status()

            print("Status code:-->"+status_code)

            print("Error occurred in PUT --> "+resp)

    except requests.exceptions.HTTPError as err:

        print ("Error in connection --> "+str(err))

    finally:

        if r: r.close()



# Create a network object

def createNetworkObject(name,value,description):

    """Create a network object: example createNetworkObject('insideNet','10.0.0.0/24','Inside Network')

       resp and json_resp are updated"""

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networks"

    url = server + api_path  

    post_data = {

        "name": name,

        "value": value,

        "overridable": False,

        "description": description,

        "type": "Network"

    }

    RESTpost(url,post_data)



# Create a host object

def createHostObject(name,ip,description):

    """createHostObject example createHostObject('webserver1','10.0.1.250','Web Server 1')

       resp and json_resp are updated"""

    

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"

    url = server + api_path

    post_data = {

        "name": name,

        "type": "Host",

        "value": ip,

        "description": description

    }

    RESTpost(url,post_data)



def createSecurityZoneObject(name,description):

    """createSecurityZoneObject example createSecurityZoneObject('Inside','Inside Security Zone')

       resp and json_resp are updated"""

    

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones"

    url = server + api_path

    post_data = {

        "type": "SecurityZone",

        "name": name,

        "description": description,

        "interfaceMode": "ROUTED"

    }

    RESTpost(url,post_data)



def getSecurityObjectIdByName(name):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones"

    url = server + api_path

    RESTget(url)

    if 'items' in json_resp:

        for item in json_resp['items']:

            if item['name'] == name:

                return str(item['id'])

    return ''

    #raise Exception('security zone object with name ' + name + ' was not found')



def registerDevice(name, mgmtIp, policyId, regId, natId):

    """Register a Device: example registerDevice('ngfwv','10.0.250.5',policyId)

       resp and json_resp are updated"""

    print("Registering "+name)

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"

    url = server + api_path

    post_data = {

        "name": name,

        "hostName": mgmtIp,

        "regKey": regId,

        "natID": natId,

        "type": "Device",

        "license_caps": [

            "BASE",

            "MALWARE",

            "URLFilter",

            "THREAT"

        ],

        "accessPolicy": {

            "id": policyId,

            "type": "AccessPolicy"

        }

    }

    print("Register ngfwv01 - submitting request")

    RESTpost(url,post_data)



# get Device(FTDv) id by name

def getDeviceIdByName(name):

    """ Returns the device uuid by device name or returns an exception"""    

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"

    url = server + api_path

    RESTget(url)

    for item in json_resp['items']:

        if item['name'] == name:

            return str(item['id'])

    raise Exception('device with name ' + name + ' was not found')



# Get network objects (all network and host objects)

def getNetworkObjectIdByName(name):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses"

    url = server + api_path

    RESTget(url)

    for item in json_resp['items']:

        if item['type'] == 'Network' and item['name'] == name:

            return str(item['id'])

    raise Exception('network object with name ' + name + ' was not found')



def getHostObjectIdByName(name):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"

    url = server + api_path

    RESTget(url)

    for item in json_resp['items']:

        if item['type'] == 'Host' and item['name'] == name:

            return str(item['id'])

    raise Exception('host object with name ' + name + ' was not found')



# Get network objects (all network and host objects)

def getPortObjectIdByName(name):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ports"

    url = server + api_path

    RESTget(url)

    for item in json_resp['items']:

        if item['type'] == 'ProtocolPortObject' and item['name'] == name:

            return str(item['id'])

    raise Exception('port object with name ' + name + ' was not found')



# Create Static route

def createStaticRoute(ngfwid,interfaceName,networkObjectName,hostObjectName,metric):

    """Create static route"""

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + ngfwid + "/routing/ipv4staticroutes"    # param

    url = server + api_path

    post_data = {

    "interfaceName": interfaceName,

    "selectedNetworks": [

        {

        "type": "Network",

        "id": getNetworkObjectIdByName(networkObjectName),

        "name": networkObjectName

        }

    ],

    "gateway": {

        "object": {

        "type": "Host",

        "id": getHostObjectIdByName(hostObjectName),

        "name": hostObjectName

        }

    },

    "metricValue": metric,

    "type": "IPv4StaticRoute",

    "isTunneled": False

    }

    RESTpost(url,post_data)



# Create an Access Policy

def createAccessPolicy(name,defaultAction):

    """Create an Access Policy with a default action example: createAccessPolicy('policy2','NETWORK_DISCOVERY')

    Default actions should be one of BLOCK, PERMIT, TRUST, MONITOR, BLOCK_WITH_RESET, INTERACTIVE_BLOCK, 

    INTERACTIVE_BLOCK_WITH_RESET, NETWORK_DISCOVERY, IPS_ACTION, FASTPATH """

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"

    url = server + api_path

    post_data = {

        "type": "AccessPolicy",

        "name": name,

        "defaultAction": {

            "action": defaultAction

        }

    }

    RESTpost(url,post_data)



def getTaskStatusById(id):

    status = ''

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/job/taskstatuses/"+id

    url = server + api_path

    try:

        RESTget(url)

        status = json_resp['status']

        return status

    except Exception:

        status = ''

        return status



# get policy id by name

def getAccessPolicyIdByName(name):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"

    url = server + api_path

    RESTget(url)

    # Search for policy by name

    if 'items' in json_resp:

        for item in json_resp['items']:

            if item['name'] == name:

                return str(item['id'])

    return ''

    # raise Exception('Policy with name ' + name + ' was not found')



# Associate Access Policy with a device 

def associateAccessPolicyWithDevice(policyName,deviceName):    

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments" 

    url = server + api_path

    post_data = {

        "type": "PolicyAssignment",

        "policy": {

            "type": "AccessPolicy",

            "id": getAccessPolicyIdByName(policyName)

        },

        "targets": [

            {

            "id": getDeviceIdByName(deviceName) ,

            "type": "Device"

            }

        ]

    }

    RESTpost(url,post_data)



# Create an ftdv nat policy 

def createFtdNatPolicy(name,description):

    global resp, json_resp

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies"

    url = server + api_path

    post_data = {

        "type": "FTDNatPolicy",

        "name": name,

        "description": description

    }

    RESTpost(url,post_data)



def getFtdNatPolicyByName(name):

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies"

    url = server + api_path

    RESTget(url)

    # Search for policy by name

    for item in json_resp['items']:

        if item['name'] == name:

            return str(item['id'])

    raise Exception('Policy with name ' + name + ' was not found')



def associateFtdNatPolicyWithDevice(policyName,deviceName): 

    """ """   

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments" 

    url = server + api_path

    post_data = {

        "type": "PolicyAssignment",

        "policy": {

            "type": "FTDNatPolicy",

            "id": getFtdNatPolicyByName(policyName)

        },

        "targets": [

            {

            "id": getDeviceIdByName(deviceName) ,

            "type": "Device"

            }

        ]

    }

    RESTpost(url,post_data)





def associateFtdNatPolicyWith2Device(policyName,deviceName1,deviceName2): 

    """ """   

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments" 

    url = server + api_path

    post_data = {

        "type": "PolicyAssignment",

        "policy": {

            "type": "FTDNatPolicy",

            "id": getFtdNatPolicyByName(policyName)

        },

        "targets": [

            {

            "id": getDeviceIdByName(deviceName1) ,

            "type": "Device"

            },

            {

            "id": getDeviceIdByName(deviceName2) ,

            "type": "Device"

            }

        ]

    }

    RESTpost(url,post_data)





# Get the auth token for our REST transactions

def getAuthToken():

    global headers

    """get_authtoken will get a new REST authentication token

       and update the variables auth_token and headers"""

    global auth_token

    r = None

    headers = {'Content-Type': 'application/json'}

    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"

    auth_url = server + api_auth_path

    try:

        # 2 ways of making a REST call are provided:

        # One with "SSL verification turned off" and the other with "SSL verification turned on".

        # The one with "SSL verification turned off" is commented out. If you like to use that then 

        # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'

        # REST call with SSL verification turned off: 

        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)

        # REST call with SSL verification turned on: Download SSL certificates from your FMC first and provide its path for verification.

        # r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')

        auth_headers = r.headers

        auth_token = auth_headers.get('X-auth-access-token', default=None)

        domain_uuid = auth_headers.get('domain_uuid', default=None)

        headers['X-auth-access-token']=auth_token

        print("Acquired AuthToken: " + auth_token)

        print("domain_uuid: " + domain_uuid)

    

        if auth_token == None:

            print("auth_token not found. Exiting...")

            sys.exit()

    except Exception as err:

        print ("Error in generating auth token --> "+str(err))

        sys.exit()



# Get timestamp that can be used for deployment - time*1000

def FmcGetTimeStamp():

    api_path = "/api/fmc_platform/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/audit/auditrecords"

    url = server + api_path

    RESTget(url)

    return json_resp['items'][0]['time']*1000



# Deploy to any devices ready for deployment

def FmcDeploy():

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deployabledevices"

    url = server + api_path

    RESTget(url)

    idList = []

    for item in json_resp['items']:

        if item['type'] == 'DeployableDevice':

            idList.append(getDeviceIdByName(item['name'])) 

    print("This is the list to deploy: "+ str(idList) )

    if idList != []:

        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"

        url = server + api_path

        post_data = {

            "type": "DeploymentRequest",

            "version": str(FmcGetTimeStamp()),

            "forceDeploy": True,

            "ignoreWarning": True,

            "deviceList": idList 

        }

        RESTpost(url,post_data)



#=========================================================================

# End of Definition of a helpful functions

#=========================================================================



#=========================================================================

#==================== Start setting things up ============================

#=========================================================================



#=========================================================================

# Get an Authentication Token - to be used in subsequent REST transactions

#=========================================================================              

getAuthToken()





#==============================================================

#  Configure the interfaces 

#============================================================== 



# Get the device IDs of each NGFW

ngfwv01Id = getDeviceIdByName(ngfwv01Name)

print("Working with ngfw " + ngfwv01Name + " with id: " + ngfwv01Id )


# create security zones and get their ids

if getSecurityObjectIdByName('InZone') == '':

    createSecurityZoneObject('InZone','Inside Security Zone')

ngfwvInsideZoneId = getSecurityObjectIdByName('InZone')

print("Working with Inside Security Zone with id: " + ngfwvInsideZoneId )

#=========================================================

# Configure physical interfaces for ngfwv01

#=========================================================

# get the physical interface ids and links for eth1/2

api_path = "/api/fmc_config/v1/domain/7929e0a2-1fd7-f056-0e57-000000000001/devices/devicerecords/" + ngfwv01Id + "/physicalinterfaces"

url = server + api_path

RESTget(url)

for item in json_resp['items']:

    if item['name'] == "GigabitEthernet0/1":

        ngfwv01Gig00id = str(item['id'])

        ngfwv01Gig00Link = str(item['links']['self'])

        print("Interface: GigabitEthernet0/1   id: " + ngfwv01Gig00id + "   link: " + ngfwv01Gig00Link )



# Configure ftd-1 inside eth1/2 - uses ip, mask, interface id, zone id

url =  ngfwv01Gig00Link

put_data = {

                "type": "PhysicalInterface",

                "managementOnly": "false",

                "MTU": 1500,

                "ipv4": {

                    "static": {

                        "address": ngfwv01InsideIP,

                        "netmask": ngfwv01InsideMask

                        }

                },

                "securityZone": {

                    "id": ngfwvInsideZoneId,

                    "type": "SecurityZone"

                },

                "mode": "NONE",

                "ifname": "inside",

                "enabled": "true",

                "name": "GigabitEthernet0/1",

                "id": ngfwv01Gig00id

                }

RESTput(url,put_data)

#==============================================================

# Done configuring... deploy

#==============================================================

#FmcDeploy()

