"""SSH2FA client for Windows
   Copyright (C) 2023 Thomas Stephenson
"""

import argparse
import os
import subprocess
import sys
import threading
import winpty

PASSWORD_FILE_MAX_SIZE = 256
HOST_AUTHENTICITY_PROMPT_MATCH = 'The authenticity of host '
HOST_KEY_CHANGED_PROMPT_MATCH = 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!'

SSH_DONE, SSH_ERROR, SSH_HOST_UNKNOWN, SSH_HOST_UNSAFE, OTP_COMMAND_ERROR, OTP_UNSET, ARGS_EXCEPT = range(7)

class SecuritySettings(object):
    """ Security settings for SSH connection
    """

    def __init__(self, password_prompt='assword', otp_prompt='erification code'):
        self.password_mode = None
        self.otp_mode = None
        self.password_prompt = password_prompt
        self.otp_prompt = otp_prompt


    def ensure_virgin_password(self):
        if self.password_mode:
            raise Exception('Password mode already set')
        
    
    def ensure_virgin_otp(self):
        if self.otp_mode:
            raise Exception('OTP mode already set')


    def set_password(self, password):
        self.ensure_virgin_password()
        self.password_mode = 'password'
        self.password = password


    def set_password_env_var(self, env_var):
        self.ensure_virgin_password()
        self.password_mode = 'password_env_var'
        self.password_env_var = env_var

        self.password = os.environ.get(self.password_env_var)
        if self.password is None:
            raise Exception('Environment variable not set: ' + self.password_env_var)
        
        del os.environ[self.password_env_var]

    
    def set_password_file(self, filename):
        self.ensure_virgin_password()
        self.password_mode = 'password_file'
        
        try:
            with open(filename, 'r') as f:
                self.password = f.read()
            
            read_size = len(self.password)
            if read_size > PASSWORD_FILE_MAX_SIZE:
                raise Exception('Password from file too large: ' + filename)
            elif read_size == 0:
                raise Exception('Password file empty: ' + filename)
            if self.password[-1] == '\n':
                self.password = self.password[:-1]
            if self.password[-1] == '\r':
                self.password = self.password[:-1]
            
        except IOError as e:
            raise Exception('Error reading password file: ' + filename + ' (' + str(e) + ')')

    
    def set_otp(self, otp):
        self.ensure_virgin_otp()
        self.otp_mode = 'otp'
        self.otp = otp

    
    def set_otp_command(self, command):
        self.ensure_virgin_otp()
        self.otp_mode = 'otp_command'
        self.otp_command = command

    
    def clear_password(self):
        self.password = None

    
    def clear_otp(self):
        self.otp = None
        self.otp_command = None


    def safe_environment(self):
        """ Return a copy of the environment with sensitive variables removed
        """
        env = os.environ.copy()
        if self.password_mode == 'password_env_var':
            del env[self.password_env_var]
        
        return env
    

    def run_otp_command(self):
        """ Run OTP command and set OTP if successful
        """
        try:
            output = subprocess.check_output(self.otp_command, shell=True, env=self.safe_environment())
            self.otp = output.decode('utf-8').strip()
            return 0
        except subprocess.CalledProcessError as e:
            print('OTP command failed: ' + str(e))
            return e.returncode


def read_buf_until_match(process: winpty.PtyProcess, matches: [str], bufsize=1024, verbose=False) -> int:
        data = process.fileobj.recv(bufsize)
        if not data:
            return -1
        
        # see PyWinpty read()
        if data == b'0011Ignore':
            data = ''
        
        while True:
            try:
                content = data.decode('utf-8')

                for i in range(len(matches)):
                    if matches[i] in content:
                        return i
                   
                more_data = None
                while not more_data or more_data == b'0011Ignore':
                    more_data = process.fileobj.recv(bufsize)
                    if not more_data:
                        if verbose:
                            print(content, end='')
                        return -1
               
                data += more_data
                # Make sure buffer doesn't get too large
                if len(data) > bufsize * 2:
                    data = data[-bufsize:]
               
            except:
                # Decode error - probably not UTF-8 yet
                more_data = process.fileobj.recv(1)
                if not more_data:
                    return -1
               
                data += more_data


class SSHClient(object):

    def __init__(self, host, security_settings: SecuritySettings, verbose=False):
        self.host = host
        self.security_settings = security_settings
        self.verbose = verbose


    def run(self):
        # Create process
        child_environ = self.security_settings.safe_environment()
        process = winpty.PtyProcess.spawn(['ssh', self.host], cwd=os.getcwd(), env=child_environ)

        if self.security_settings.password_mode:
            result = self.await_password_entry(process)
            if result != SSH_DONE:
                process.close()
                return result
        elif self.verbose:
            print('Skipping password entry')
        
        if self.security_settings.otp_mode:
            result = self.await_otp_entry(process)
            if result != SSH_DONE:
                process.close()
                return result
        elif self.verbose:
            print('Skipping OTP entry')

        try:
            # Wait for shell prompt
            while True:
                line = process.readline()
                if self.verbose:
                    print(line, end='')
                if line.endswith('$ '):
                    break
                if not line and process.exitstatus != None:
                    return SSH_ERROR

            # Enter interactive mode
            while True:
                line = process.readline()
                if self.verbose:
                    print(line, end='')
                if not line and process.exitstatus != None:
                    return SSH_DONE
                process.write(input() + "\n")

        except EOFError:
            if process.exitstatus:
                return SSH_ERROR
        
        finally:
            process.close()

        return SSH_DONE


    def await_password_entry(self, process: winpty.PtyProcess) -> int:
        # Wait for password prompt
        password_prompt = self.security_settings.password_prompt
        match_patterns = [HOST_AUTHENTICITY_PROMPT_MATCH, HOST_KEY_CHANGED_PROMPT_MATCH, password_prompt]
        match_idx = read_buf_until_match(process, match_patterns)
        
        match match_idx:
            case 0:
                print('Host authenticity prompt detected - aborting')
                return SSH_HOST_UNKNOWN
            case 1:
                print('Host key changed prompt detected - aborting')
                return SSH_HOST_UNSAFE
            case 2:
                pass
            case _:
                return process.exitstatus or SSH_ERROR

        try:
            # Send password
            process.write(self.security_settings.password + '\n')
            
        except EOFError as e:
            print('EOFError: ' + str(e))
            return SSH_ERROR
        
        finally:
            # Clear password
            self.security_settings.clear_password()
        
        return SSH_DONE
    

    def await_otp_entry(self, process: winpty.PtyProcess) -> int:
        # Wait for OTP prompt
        otp_prompt = self.security_settings.otp_prompt

        match_patterns = [otp_prompt]
        match_idx = read_buf_until_match(process, match_patterns)
        
        if match_idx != 0:
            return process.exitstatus or SSH_ERROR

        try:
            # Send OTP
            otp_mode = self.security_settings.otp_mode
            if otp_mode == 'otp_command' and self.security_settings.run_otp_command() != 0:
                return OTP_COMMAND_ERROR
        
            if self.security_settings.otp is None:
                return OTP_UNSET
        
            process.write(self.security_settings.otp + "\n")
        
        except EOFError as e:
            print('EOFError: ' + str(e))
            return SSH_ERROR
        
        finally:
            # Clear OTP
            self.security_settings.clear_otp()
        
        return SSH_DONE


def main():
    # sshpywin.py [-h] [-v] [-P PASSWORD_PROMPT] [-p PASSWORD] [-e PASS_ENV_VAR] [-f PASS_FILE] [-O OTP_PROMPT] [-o OTP] [-c OTP_COMMAND] host
    argparser = argparse.ArgumentParser()
    argparser.add_argument('host')
    argparser.add_argument('-v', '--verbose', action='store_true', help='Use verbose output')
    argparser.add_argument('-P', '--password-prompt', default='assword', help='Password prompt to look for')
    argparser.add_argument('-p', '--password', help='Password to use')
    argparser.add_argument('-e', '--pass-env-var', help='Environment variable containing password')
    argparser.add_argument('-f', '--pass-file', help='File containing password')
    argparser.add_argument('-O', '--otp-prompt', default='erification code', help='OTP prompt to look for')
    argparser.add_argument('-o', '--otp', help='OTP to use')
    argparser.add_argument('-c', '--otp-command', help='Command to generate OTP')
    args = argparser.parse_args()

    # Clear argv (might not help)
    sys.argv = sys.argv[:1]

    # Create security settings
    security_settings = SecuritySettings(args.password_prompt, args.otp_prompt)
    try:
        if args.password:
            security_settings.set_password(args.password)
        if args.pass_env_var:
            security_settings.set_password_env_var(args.pass_env_var)
        if args.pass_file:
            security_settings.set_password_file(args.pass_file)
    except:
        print('Only expected one of -p, -e, -f', file=sys.stderr)
        return ARGS_EXCEPT

    try:
        if args.otp:
            security_settings.set_otp(args.otp)
        if args.otp_command:
            security_settings.set_otp_command(args.otp_command)
    except:
        print('Only expected one of -o, -c', file=sys.stderr)
        return ARGS_EXCEPT

    # Create SSH client
    ssh_client = SSHClient(args.host, security_settings, args.verbose)

    # Run SSH client
    result = ssh_client.run()
    if args.verbose and result != 0:
       print(f'SSH client exited with code: {result}', file=sys.stderr)
    
    return result


if __name__ == '__main__':
    code = main()
    sys.exit(code)
