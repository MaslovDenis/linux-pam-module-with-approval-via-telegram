import syslog
import grp
import socket
import json
import pyotp
import base64
import select


otp_secret = 'Your encrypted OTP secret'


def auth_log(msg):
    """ Save to log /var/log/auth.log """
    syslog.openlog(facility=syslog.LOG_AUTH)
    syslog.syslog("Authentication with approve: " + str(msg))
    syslog.closelog()


def get_approve(pamh, user, group_name, server_ip, server_port):
    """ Getting confirmation of login permission """

    if group_name in [g.gr_name for g in grp.getgrall() if user in g.gr_mem]:

        """ Server availability check """
        if check_approve_tcp_server(server_ip=server_ip, server_port=server_port) == 0:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            """ server connection """
            client.connect((server_ip, int(server_port)))

            auth_log("Connect to socket")

            data = {
                "user": user,
                "host": socket.gethostname()
            }

            """sending data. Username and computer name """
            client.send(bytes(json.dumps(data)))

            """ getting a response """
            ready = select.select([client], [], [], 60)

            if ready[0]:
                data = client.recv(1024)
            else:
                """ If approver is not available, the MFA login is used """
                """ We receive the entered MFA code by the user """
                resp = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "Enter one time PIN: "))

                """ Checking the MFA code entered by the user """
                if (pyotp.TOTP(decrypt(otp_secret).decode()).now()) == resp.resp:
                    return pamh.PAM_SUCCESS
                return pamh.PAM_ABORT

            if data == 'Approve':
                auth_log("Access approved")
                return pamh.PAM_SUCCESS
            else:
                auth_log("Access not approved")
                pamh.conversation(pamh.Message(pamh.PAM_ERROR_MSG, "Access not approved."))
                return pamh.PAM_AUTH_ERR

        return pamh.PAM_ABORT

    else:
        return pamh.PAM_SUCCESS


def check_approve_tcp_server(server_ip, server_port):
    """
    Server availability check
    0 - Ready
    111 - Not ready"""

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return client.connect_ex((server_ip, int(server_port)))


def encrypt(source, encode=True):
    return base64.b64encode(source).decode("latin-1") if encode else source

def decrypt(source):
    source = base64.b64decode(source.encode("latin-1"))
    return source


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user()
    except pamh.exception as ex:
        return ex.pam_result

    if user is None:
        return pamh.PAM_ABORT

    """ Checking the required arguments """

    properties = json.loads(argv[1])
    if 'group' not in properties or \
            'server-ip' not in properties or \
            'server-port' not in properties:
        auth_log("Some properties doesn't exist! Please specify group, server-ip and server-port")
        return pamh.PAM_ABORT


    if not properties['group']:
        auth_log("Group doesn't exist! Please specify group")
        return pamh.PAM_ABORT


    if properties['group'] in [g.gr_name for g in grp.getgrall() if user in g.gr_mem]:
        if check_approve_tcp_server(server_ip=properties['server-ip'],
                                    server_port=properties['server-port']) == 0:
            return get_approve(pamh, user,
                               group_name=properties['group'],
                               server_ip=properties['server-ip'],
                               server_port=properties['server-port'])

        """ If the server is not available, the MFA login is used """
        auth_log('TCP server not ready')
        pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, 'TCP server not ready'))

        """ We receive the entered MFA code by the user """
        resp = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "Enter one time PIN: "))

        """ Checking the MFA code entered by the user """
        if (pyotp.TOTP(decrypt(otp_secret).decode()).now()) == resp.resp:
            return pamh.PAM_SUCCESS
        return pamh.PAM_ABORT
    else:
        return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
