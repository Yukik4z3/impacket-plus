# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Mini shell using some of the SMB funcionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#
from __future__ import division
from __future__ import print_function
from io import BytesIO
import sys
import time
import cmd
import os
import ntpath
import re

from six import PY2
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket import LOG
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY
from tqdm import tqdm

import charset_normalizer as chardet

class TqdmFileWrapper:
    def __init__(self, file_obj, total_size):
        self.file_obj = file_obj
        # 自定义格式：文件大小显示两位小数，速度显示整数
        self.pbar = tqdm(
            total=total_size,
            unit='B',
            unit_scale=True,
            unit_divisor=1024,  # 使用1024而不是1000作为单位换算
            desc="Downloading",
            bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
        )
        # 设置自定义格式函数
        self._setup_custom_format()

    def _setup_custom_format(self):
        """设置自定义的大小和速度格式"""
        original_format_sizeof = tqdm.format_sizeof
        original_format_interval = tqdm.format_interval

        def custom_format_sizeof(num, suffix='', divisor=1024):
            """自定义文件大小格式，显示两位小数"""
            for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
                if abs(num) < divisor:
                    return f"{num:.2f}{unit}{suffix}"
                num /= divisor
            return f"{num:.2f}Y{suffix}"

        # 临时替换格式函数
        tqdm.format_sizeof = custom_format_sizeof

    def write(self, data):
        self.file_obj.write(data)
        self.pbar.update(len(data))

    def close(self):
        self.pbar.close()
        self.file_obj.close()

    def __getattr__(self, name):
        return getattr(self.file_obj, name)

def smb_getAllDir(smbConnection :SMBConnection, shareName, path, base_dir=''):
    obj = smbConnection.listPath(shareName, path)[0]
    if obj.is_directory() > 0:
        os.makedirs(os.path.join(base_dir, obj.get_longname()), exist_ok=True)
        for i in smbConnection.listPath(shareName, f'{path}\\*'):
            if i.get_longname() == '.' or i.get_longname() == '..':
                continue
            smb_getAllDir(smbConnection, shareName, f'{path}\\{i.get_longname()}', os.path.join(base_dir, obj.get_longname()))
    else:
            file_size = obj.get_allocsize()
            print("[+] Getting file:", path)
            with open(f'{base_dir}/{obj.get_longname()}', 'wb') as f:
                wrapped_file = TqdmFileWrapper(f, file_size)
                try:
                    smbConnection.getFile(shareName, path, wrapped_file.write)
                except Exception as e:
                    print("[-] Error: " + str(e))
                    os.remove(f'{base_dir}/{obj.get_longname()}')

class MiniImpacketShell(cmd.Cmd):
    def __init__(self, smbClient, tcpShell=None, outputfile=None):
        #If the tcpShell parameter is passed (used in ntlmrelayx),
        # all input and output is redirected to a tcp socket
        # instead of to stdin / stdout
        if tcpShell is not None:
            cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
            sys.stdout = tcpShell.stdout
            sys.stdin = tcpShell.stdin
            sys.stderr = tcpShell.stdout
            self.use_rawinput = False
            self.shell = tcpShell
        else:
            cmd.Cmd.__init__(self)
            self.shell = None

        self.prompt = '# '
        self.smb = smbClient
        self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = smbClient.getCredentials()
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.outputfile = outputfile

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
            f.write('> ' + line + "\n")
            f.close()
        if PY2:
            return line.decode('utf-8')
        return line

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception as e:
           LOG.error(e)
           LOG.debug('Exception info', exc_info=True)

        return retVal

    def do_exit(self,line):
        if self.smb is not None:
            try:
                self.do_logoff(None)
            except:
                pass
        if self.shell is not None:
            self.shell.close()
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print(output)
        self.last_output = output

    def do_help(self,line):
        print("""
 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 lls {dirname} - lists all the files on the local filesystem.
 search {keywords} - Search for files containing the specified keywords in the current directory and all subdirectories. Use /regex pattern/ to search with a regular expression.
 tree {filepath[,output][:depth]} - recursively lists all files in folder and sub folders, if give output, save output to file, use depth to set list depth
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename/path} - downloads the filename/path from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)
""")

    def do_password(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        from getpass import getpass
        newPassword = getpass("New Password:")
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\samr', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        samr.hSamrUnicodeChangePasswordUser2(dce, '\x00', self.username, self.password, newPassword, self.lmhash, self.nthash)
        self.password = newPassword
        self.lmhash = None
        self.nthash = None

    def do_open(self,line):
        l = line.split(' ')
        port = 445
        if len(l) > 0:
           host = l[0]
        if len(l) > 1:
           port = int(l[1])


        if port == 139:
            self.smb = SMBConnection('*SMBSERVER', host, sess_port=port)
        else:
            self.smb = SMBConnection(host, host, sess_port=port)

        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            LOG.info("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            LOG.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            LOG.info("SMBv2.1 dialect used")
        else:
            LOG.info("SMBv3.0 dialect used")

        self.share = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.login(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_kerberos_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if domain == '':
            LOG.error("Domain must be specified for Kerberos login")
            return

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.kerberosLogin(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_login_hash(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           hashes = l[1]
        else:
           LOG.error("Hashes needed. Format is lmhash:nthash")
           return

        if username.find('/') > 0:
           domain, username = username.split('/')

        lmhash, nthash = hashes.split(':')

        self.smb.login(username, '', domain,lmhash=lmhash, nthash=nthash)
        self.username = username
        self.lmhash = lmhash
        self.nthash = nthash

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_logoff(self, line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        self.smb.logoff()
        del self.smb
        self.share = None
        self.smb = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_info(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrServerGetInfo(dce, 102)

        print("Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major'])
        print("Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor'])
        print("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
        print("Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment'])
        print("Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath'])
        print("Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users'])

    def do_who(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            print("host: %15s, user: %5s, active: %5d, idle: %5d" % (
            session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
            session['sesi10_idle_time']))

    def do_shares(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        resp = self.smb.listShares()
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        for i in range(len(resp)):
            if self.outputfile:
                f.write(resp[i]['shi1_netname'][:-1] + '\n')
            print(resp[i]['shi1_netname'][:-1])
        if self.outputfile:
            f.close()

    def do_use(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        self.share = line
        self.tid = self.smb.connectTree(line)
        self.pwd = '\\'
        self.prompt = f"[{self.pwd}] # "
        self.do_ls('', False)

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include = 2)

    def do_cd(self, line):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = line.replace('/','\\')
        oldpwd = self.pwd
        if p[0] == '\\':
           self.pwd = line
        else:
           self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)
        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd, creationOption = FILE_DIRECTORY_FILE, desiredAccess = FILE_READ_DATA |
                                   FILE_LIST_DIRECTORY, shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE )
            self.smb.closeFile(self.tid,fid)
            self.prompt = f"[{self.pwd}] # "
        except SessionError:
            self.pwd = oldpwd
            self.prompt = f"[{self.pwd}] # "
            raise

    def do_lcd(self, s):
        print(s)
        if s == '':
           print(os.getcwd())
        else:
           os.chdir(s)

    def do_pwd(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        print(self.pwd.replace("\\","/"))
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
            f.write(self.pwd.replace("\\","/"))
            f.close()

    def do_ls(self, wildcard, display = True):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        if wildcard == '':
           pwd = ntpath.join(self.pwd,'*')
        else:
           pwd = ntpath.join(self.pwd, wildcard)
        self.completion = []
        pwd = pwd.replace('/','\\')
        pwd = ntpath.normpath(pwd)
        if self.outputfile is not None:
            of = open(self.outputfile, 'a')
        for f in self.smb.listPath(self.share, pwd):
            if display is True:
                if self.outputfile:
                    of.write("%crw-rw-rw- %10d  %s %s" % (
                    'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                    f.get_longname()) + "\n")

                print("%crw-rw-rw- %10d  %s %s" % (
                'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                f.get_longname()))
            self.completion.append((f.get_longname(), f.is_directory()))
        if self.outputfile:
            of.close()

    def do_lls(self, currentDir):
        if currentDir == "":
            currentDir = "./"
        else:
            pass
        for LINE in os.listdir(currentDir):
            print(LINE)

    def do_tree(self, filepath):
        output = None
        max_depth = None
        if ':' in filepath:
            filepath, max_depth = filepath.split(':')
            max_depth = int(max_depth)
        if ',' in filepath:
            filepath, output = filepath.split(',')
            if os.path.exists(output):
                os.remove(output)
        filepath = filepath.replace('/', '\\')
        if not filepath.startswith('\\'):
            filepath = self.pwd + '\\' + filepath
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return

        from collections import deque

        queue = deque([(filepath, "", 0)])
        while queue:
            current_remote_path, current_local_path, depth = queue.popleft()
            try:
                if max_depth is not None and depth > max_depth:
                    continue
                file_obj = self.smb.listPath(self.share, current_remote_path)[0]
                if file_obj.is_directory():
                    for i in self.smb.listPath(self.share, f'{current_remote_path}\\*'):
                        if i.get_longname() == '.' or i.get_longname() == '..':
                            continue
                        queue.append((f'{current_remote_path}\\{i.get_longname()}',
                                      f'{current_local_path}\\{file_obj.get_longname()}', depth + 1))
                        if depth == max_depth:
                            if output is not None:
                                with open(output, 'a') as f:
                                    f.write(f'{current_remote_path}\\{i.get_longname()}' + '\n')
                            else:
                                print(f'{current_remote_path}\\{i.get_longname()}')
                else:
                    if output is not None:
                        with open(output, 'a') as f:
                            f.write(f'{current_remote_path}\\{file_obj.get_longname()}' + '\n')
                    else:
                        print(f'{current_remote_path}\\{file_obj.get_longname()}')
            except KeyboardInterrupt:
                print()
                break
            except SessionError as e:
                continue
            except Exception as e:
                print(f"[-] Error accessing {current_remote_path}: {str(e)}")
                continue

    def do_search(self, keyword):
        folderList = []
        if keyword == "":
            return
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return

        use_regex = False
        if keyword.startswith('/') and keyword.endswith('/') and len(keyword) > 2:
            regex_pattern = keyword[1:-1]  # 去掉首尾的 /
            try:
                pattern = re.compile(regex_pattern, re.IGNORECASE)  # 不区分大小写
                use_regex = True
                LOG.info(f"[+] Using regex pattern: {regex_pattern}")
            except re.error as e:
                LOG.error(f"[-] Invalid regex pattern '{regex_pattern}': {e}")
                return


        from collections import deque

        queue = deque([(self.pwd, "")])
        while queue:
            current_remote_path, current_local_path = queue.popleft()
            try:
                file_obj = self.smb.listPath(self.share, current_remote_path)[0]
                if file_obj.is_directory() > 0:
                    for i in self.smb.listPath(self.share, f'{current_remote_path}\\*'):
                        if i.get_longname() == '.' or i.get_longname() == '..':
                            continue
                        queue.append((f'{current_remote_path}\\{i.get_longname()}',
                                      f'{current_local_path}\\{file_obj.get_longname()}'))

                        match_found = False
                        if use_regex:
                            if pattern.search(i.get_longname()):
                                match_found = True
                        elif keyword.lower() in i.get_longname().lower():
                            match_found = True

                        if match_found:
                            print(f'{current_remote_path}\\{i.get_longname()}')
                else:
                    match_found = False
                    if use_regex:
                        if pattern.search(i.get_longname()):
                            match_found = True
                    elif keyword.lower() in i.get_longname().lower():
                        match_found = True

                    if match_found:
                        print(f'{current_remote_path}\\{file_obj.get_longname()}')
            except KeyboardInterrupt:
                print()
                break
            except SessionError as e:
                continue
            except Exception as e:
                print(f"[-] Error accessing {current_remote_path}: {str(e)}")
                continue


    def do_rm(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        f = ntpath.join(self.pwd, filename)
        file = f.replace('/','\\')
        self.smb.deleteFile(self.share, file)

    def do_mkdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.createDirectory(self.share,pathname)

    def do_rmdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.deleteDirectory(self.share, pathname)

    def do_put(self, pathname):
        if self.tid is None:
            LOG.error("No share selected")
            return
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd,dst_name)
        finalpath = f.replace('/','\\')
        self.smb.putFile(self.share, finalpath, fh.read)
        fh.close()

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        p = line.replace('/','\\')
        if p.find('\\') < 0:
            items = []
            if include == 1:
                mask = 0
            else:
                mask = 0x010
            for i in self.completion:
                if i[1] == mask:
                    items.append(i[0])
            if text:
                return  [
                    item for item in items
                    if item.upper().startswith(text.upper())
                ]
            else:
                return items

    def do_mget(self, mask):
        if mask == '':
            LOG.error("A mask must be provided")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        self.do_ls(mask,display=False)
        if len(self.completion) == 0:
            LOG.error("No files found matching the provided mask")
            return
        for file_tuple in self.completion:
            if file_tuple[1] == 0:
                filename = file_tuple[0]
                filename = filename.replace('/', '\\')
                fh = open(ntpath.basename(filename), 'wb')
                pathname = ntpath.join(self.pwd, filename)
                try:
                    LOG.info("Downloading %s" % (filename))
                    self.smb.getFile(self.share, pathname, fh.write)
                except:
                    fh.close()
                    os.remove(filename)
                    raise
                fh.close()

    def do_get(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        pathname = ntpath.join(self.pwd,filename)
        smb_getAllDir(self.smb, self.share, pathname)

    def complete_cat(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include=1)

    def do_cat(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = BytesIO()
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFile(self.share, pathname, fh.write)
        except:
            raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        if encoding:
            try:
                if self.outputfile:
                    f.write(output.decode(encoding) + '\n')
                    f.close()
                print(output.decode(encoding))
            except:
                if self.outputfile:
                    f.write(error_msg + '\n')
                    f.close()
                print(error_msg)
            finally:
                fh.close()
        else:
            if self.outputfile:
                f.write(error_msg + '\n')
                f.close()
            print(error_msg)
            fh.close()

    def do_close(self, line):
        self.do_logoff(line)

    def do_list_snapshots(self, line):
        l = line.split(' ')
        if len(l) > 0:
            pathName= l[0].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        snapshotList = self.smb.listSnapshots(self.tid, pathName)

        if not snapshotList:
            print("No snapshots found")
            return

        for timestamp in snapshotList:
            print(timestamp)

    def do_mount(self, line):
        l = line.split(' ')
        if len(l) > 1:
            target  = l[0].replace('/','\\')
            pathName= l[1].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        self.smb.createMountPoint(self.tid, pathName, target)

    def do_umount(self, mountpoint):
        mountpoint = mountpoint.replace('/','\\')

        # Relative or absolute path?
        if mountpoint.startswith('\\') is not True:
            mountpoint = ntpath.join(self.pwd, mountpoint)

        mountPath = ntpath.join(self.pwd, mountpoint)

        self.smb.removeMountPoint(self.tid, mountPath)

    def do_EOF(self, line):
        print('Bye!\n')
        return True
