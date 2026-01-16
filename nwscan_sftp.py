import os
import threading
import socket
import paramiko
from paramiko import SFTPServerInterface, SFTPAttributes, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
from paramiko.sftp import SFTP_OK, SFTP_PERMISSION_DENIED, SFTP_NO_SUCH_FILE, SFTP_FAILURE
import logging

# Setup logging
logger = logging.getLogger("SFTPServer")

class LocalSFTPHandle(paramiko.SFTPHandle):
    """
    Handles file operations (read/write) for an open file.
    """
    def __init__(self, flags):
        super().__init__(flags)
        self.file_obj = None

    def close(self):
        if self.file_obj:
            try:
                self.file_obj.close()
            except Exception:
                pass
        super().close()

    def read(self, offset, length):
        self.file_obj.seek(offset)
        return self.file_obj.read(length)

    def write(self, offset, data):
        self.file_obj.seek(offset)
        self.file_obj.write(data)
        return SFTP_OK

    def stat(self):
        try:
            return SFTPAttributes.from_stat(os.fstat(self.file_obj.fileno()))
        except OSError:
            return SFTP_FAILURE

class LocalSFTPServer(SFTPServerInterface):
    """
    Handles filesystem operations (ls, mkdir, rename, etc.).
    """
    def __init__(self, server, *largs, **kwargs):
        # The 'server' argument here is the SFTPServer object (subsystem), 
        # but paramiko passes the transport's server object as first arg to constructor if we are not careful?
        # Actually paramiko.SFTPServer(chan, server_interface_class=LocalSFTPServer, server_object=stub_server)
        # So 'server' here is likely the StubServer instance if passed correctly.
        # But wait, paramiko.SFTPServer instantiation:
        # self.server = server_object
        # ...
        # self.interface = server_interface_class(self, *largs, **kwargs)
        # So the first argument is 'self' (the SFTPServer instance).
        super().__init__(server, *largs, **kwargs)
        
        # We need access to root_dir. We can attach it to the server object (SFTPServer instance)
        # or pass it via StubServer if we can reach it.
        # SFTPServer has .server attribute which is our StubServer instance.
        self.root = getattr(server.server, 'root_dir', os.getcwd())

    def _get_local_path(self, path):
        # Prevent directory traversal attacks
        path = path.lstrip('/')
        # On Windows, path might contain backslashes, but SFTP uses forward slashes.
        # Paramiko usually normalizes, but let's be safe.
        full_path = os.path.abspath(os.path.join(self.root, path))
        if not full_path.startswith(os.path.abspath(self.root)):
            return None
        return full_path

    def list_folder(self, path):
        local_path = self._get_local_path(path)
        if not local_path:
            return SFTP_PERMISSION_DENIED
        
        try:
            file_list = os.listdir(local_path)
            return [SFTPAttributes.from_stat(os.stat(os.path.join(local_path, f)), f) 
                    for f in file_list]
        except OSError:
            return SFTP_FAILURE

    def stat(self, path):
        local_path = self._get_local_path(path)
        if not local_path:
            return SFTP_PERMISSION_DENIED
        try:
            return SFTPAttributes.from_stat(os.stat(local_path))
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except OSError:
            return SFTP_FAILURE

    def lstat(self, path):
        local_path = self._get_local_path(path)
        if not local_path:
            return SFTP_PERMISSION_DENIED
        try:
            return SFTPAttributes.from_stat(os.lstat(local_path))
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except OSError:
            return SFTP_FAILURE

    def open(self, path, flags, attr):
        local_path = self._get_local_path(path)
        if not local_path:
            return SFTP_PERMISSION_DENIED

        # Map SFTP flags to Python mode
        mode = 'r'
        if (flags & os.O_WRONLY) or (flags & os.O_RDWR):
            mode = 'w' if (flags & os.O_TRUNC) else 'r+'
        if flags & os.O_CREAT:
            if not os.path.exists(local_path):
                # If creating, default to w+b if not specified
                if 'w' not in mode and 'a' not in mode:
                     mode = 'w' + mode.replace('r', '')
        
        if 'b' not in mode:
            mode += 'b'

        try:
            handle = LocalSFTPHandle(flags)
            handle.file_obj = open(local_path, mode)
            return handle
        except OSError as e:
            return SFTP_FAILURE

    def remove(self, path):
        local_path = self._get_local_path(path)
        if not local_path:
            return SFTP_PERMISSION_DENIED
        try:
            os.remove(local_path)
            return SFTP_OK
        except OSError:
            return SFTP_FAILURE

    def rename(self, oldpath, newpath):
        local_old = self._get_local_path(oldpath)
        local_new = self._get_local_path(newpath)
        if not local_old or not local_new:
            return SFTP_PERMISSION_DENIED
        try:
            os.rename(local_old, local_new)
            return SFTP_OK
        except OSError:
            return SFTP_FAILURE

    def mkdir(self, path, attr):
        local_path = self._get_local_path(path)
        if not local_path:
            return SFTP_PERMISSION_DENIED
        try:
            os.mkdir(local_path)
            if attr is not None:
                if attr.st_mode is not None:
                    try:
                        os.chmod(local_path, attr.st_mode)
                    except:
                        pass
            return SFTP_OK
        except OSError:
            return SFTP_FAILURE

    def rmdir(self, path):
        local_path = self._get_local_path(path)
        if not local_path:
            return SFTP_PERMISSION_DENIED
        try:
            os.rmdir(local_path)
            return SFTP_OK
        except OSError:
            return SFTP_FAILURE

class StubServer(paramiko.ServerInterface):
    """
    Handles authentication and session requests.
    """
    def __init__(self, username, password, root_dir):
        self.username = username
        self.password = password
        self.root_dir = root_dir
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        if username == self.username and password == self.password:
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

class SFTPServerController:
    def __init__(self, host='0.0.0.0', port=2222, username='admin', password='password', root_dir='.'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.root_dir = os.path.abspath(root_dir)
        self.sock = None
        self.running = False
        self.thread = None
        self.active_transports = []

        if not os.path.exists(self.root_dir):
            try:
                os.makedirs(self.root_dir)
            except OSError:
                pass
                
        # Generate host key if needed
        self.host_key_path = 'sftp_host_rsa.key'
        if not os.path.exists(self.host_key_path):
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(self.host_key_path)
        self.host_key = paramiko.RSAKey(filename=self.host_key_path)

    def start(self):
        if self.running:
            return False
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(10)
            self.sock.settimeout(1.0) # Set timeout to allow loop to check running flag
        except Exception as e:
            logger.error(f"Failed to bind SFTP server: {e}")
            return False

        self.running = True
        self.thread = threading.Thread(target=self._run_server)
        self.thread.daemon = True
        self.thread.start()
        return True

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        
        # Close all active transports
        for t in self.active_transports:
            try:
                t.close()
            except:
                pass
        self.active_transports = []
        
        if self.thread:
            self.thread.join(timeout=2)

    def _run_server(self):
        logger.info(f"SFTP Server started on {self.host}:{self.port}")
        while self.running:
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                # Socket closed
                break
            except Exception as e:
                logger.error(f"Accept error: {e}")
                continue

            logger.info(f"Connection from {addr}")
            
            try:
                t = paramiko.Transport(client)
                t.add_server_key(self.host_key)
                
                # Pass credentials and root_dir to StubServer
                server = StubServer(self.username, self.password, self.root_dir)
                t.set_subsystem_handler('sftp', paramiko.SFTPServer, LocalSFTPServer)
                
                t.start_server(server=server)
                self.active_transports.append(t)
                
                # We don't need to manage the transport thread manually, paramiko does it.
                # But we should clean up closed transports from our list eventually.
                
            except Exception as e:
                logger.error(f"Transport setup error: {e}")
        
        logger.info("SFTP Server stopped")
