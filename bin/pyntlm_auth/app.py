import os
import binascii

from flask import Flask, g, request, jsonify

from samba import param
from samba.dcerpc import netlogon, ntlmssp, srvsvc
from samba.dcerpc.netlogon import (netr_Authenticator, netr_WorkstationInformation, MSV1_0_ALLOW_MSVCHAPV2)
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.dcerpc.misc import SEC_CHAN_WKSTA, SEC_CHAN_DOMAIN, SEC_CHAN_BDC

from configparser import ConfigParser

conf_path = os.getenv("CONF")
listen_port = os.getenv("LISTEN")

config = ConfigParser()
try:
    with open(conf_path, 'r') as file:
        config.read_file(file)

    if 'AD' in config:
        netbios_name = config.get('AD', 'netbios_name')
        realm = config.get('AD', 'realm')
        server_string = config.get('AD', 'server_string')
        workgroup = config.get('AD', 'workgroup')
        server_name = config.get('AD', 'server_name')  # we need a valid DNS server or,  adds a DNS record in hosts file
        workstation = config.get('AD', 'workstation')
        username = config.get('AD', 'username')
        password = config.get('AD', 'password')
        password_is_nt_hash = config.get('AD', 'password_is_nt_hash')
        domain = config.get('AD', 'domain')
    else:
        print("The specified section does not exist in the config file.")
except FileNotFoundError:
    print("The specified config file does not exist.")

except configparser.Error as e:
    print(f"Error reading config file: {e}")

app = Flask(__name__)

machineCred = None
secureChannelConn = None


def initGlobalSecureConnection():
    global machineCred
    global secureChannelConn

    lp = param.LoadParm()

    try:
        lp.load("/root/default.conf")
    except KeyError:
        raise KeyError("SMB_CONF_PATH not set")

    lp.set('netbios name', netbios_name)
    lp.set('realm', realm)
    lp.set('server string', server_string)
    lp.set('workgroup', workgroup)

    machineCred = Credentials()

    machineCred.guess(lp)
    machineCred.set_secure_channel_type(SEC_CHAN_WKSTA)
    machineCred.set_kerberos_state(DONT_USE_KERBEROS)

    machineCred.set_workstation(workstation)
    machineCred.set_username(username)
    machineCred.set_password(password)

    machineCred.set_password_will_be_nt_hash(True if password_is_nt_hash == "1" else False)
    machineCred.set_domain(domain)

    secureChannelConn = netlogon.netlogon("ncacn_np:%s[schannel,seal]" % server_name, lp, machineCred)
    return 0

initGlobalSecureConnection()


@app.route('/ntlm/auth', methods=['POST'])
def ntlm_auth_handler():
    global secureChannelConn
    global machineCred

    try:
        data = request.get_json()

        if data is None:
            return 'No JSON payload found in request', 400

        if 'username' not in data or 'request-nt-key' not in data or 'challenge' not in data or 'nt-response' not in data:
            return 'Invalid JSON payload format, missing required keys', 400

        account_username = data['username']
        request_nt_key = data['request-nt-key']
        challenge = data['challenge']
        nt_response = data['nt-response']

    except Exception as e:
        print(e)
        return "Error processing JSON payload", 500




    logon_level = netlogon.NetlogonNetworkTransitiveInformation
    validation_level = netlogon.NetlogonValidationSamInfo4

    netr_flags = 0

    auth = machineCred.new_client_authenticator()
    current = netr_Authenticator()
    current.cred.data = [x if isinstance(x, int) else ord(x) for x in auth["credential"]]
    current.timestamp = auth["timestamp"]

    subsequent = netr_Authenticator()

    challenge = binascii.unhexlify(challenge)
    response = binascii.unhexlify(nt_response)

    logon = netlogon.netr_NetworkInfo()
    logon.challenge = [x if isinstance(x, int) else ord(x) for x in challenge]
    logon.nt = netlogon.netr_ChallengeResponse()
    logon.nt.data = [x if isinstance(x, int) else ord(x) for x in response]
    logon.nt.length = len(response)

    logon.identity_info = netlogon.netr_IdentityInfo()
    logon.identity_info.domain_name.string = domain
    logon.identity_info.account_name.string = account_username
    logon.identity_info.workstation.string = workstation

    result = secureChannelConn.netr_LogonSamLogonWithFlags(server_name, workstation, current, subsequent, logon_level,
                                                           logon, validation_level, netr_flags)

    (return_auth, info, foo, bar) = result

    nt_key = [x if isinstance(x, str) else hex(x)[2:] for x in info.base.key.key]
    nt_key_str = ''.join(nt_key)

    print("---- NT KEY: ", nt_key_str)

    return nt_key_str.encode("utf-8")

# if name == __main__:
# app.run(threaded = True, host='0.0.0.0', port=5000)
app.run(debug='debug', processes=1, threaded=True, host='0.0.0.0', port=listen_port)
