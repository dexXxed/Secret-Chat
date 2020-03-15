import queue
import select
import socket
import threading
import time

import pyaes
from myprotocol import *

HOST = 'localhost'
PORT = 9876


class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=True, target=self.run)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # получаем имя локальной машины
        self.host = host
        self.port = port

        self.buffer_size = 2048

        # используется для записи в буфер
        # ключ: client_socket
        # значени: очередь зашифрованных байт
        # отправка с помощью client_sock.send()
        self.msg_queues = {}

        # записываем все подключенные сокеты
        self.connection_list = []

        # ключ: login_user
        # значение: client_socket
        self.login_dict = {}

        # ключ: client_socket
        # значение: строка пароля клиента
        self.__password_dict = {}

        # Повторно входящая блокировка должна быть снята тем потоком, который ее затронул
        # Как только поток получил блокировку повторного входа, тот же поток может получить ее снова без блокировки;
        # поток должен освобождать его каждый раз, когда он его получил.
        self.lock = threading.RLock()

        # установка сокета
        self.shutdown = False
        try:
            # привязка к порту с этим сервером
            self.server_socket.bind((str(self.host), int(self.port)))
            # очередь до 5 запросов
            self.server_socket.listen(10)

            # запускаем поток сервера
            self.start()
        except socket.error:
            self.shutdown = True

        # главный цикл
        while not self.shutdown:
            # ждем командную строку
            msg = input()
            if msg == 'quit':
                for sock in self.connection_list:
                    sock.close()
                self.shutdown = True
                self.server_socket.close()

    def remove_user(self, user, user_sock):
        if user in self.login_dict:
            del self.login_dict[user]
        if user_sock in self.connection_list:
            self.connection_list.remove(user_sock)
        if user_sock in self.msg_queues:
            del self.msg_queues[user_sock]
        if user_sock in self.__password_dict:
            del self.__password_dict[user_sock]

    def get_password(self, client_socket):
        if client_socket not in self.__password_dict:
            return None
        else:
            return self.__password_dict[client_socket]

    def set_password(self, client_sock, password):
        if client_sock not in self.__password_dict:
            self.__password_dict[client_sock] = password
        else:
            print('cannot reset password!')

    def run(self):
        print('server is running.')
        while True:
            with self.lock:
                try:
                    # пасивно принимает TCP клиентское подключение, пока ждет подключения
                    client_sock, addr = self.server_socket.accept()
                except socket.error:
                    time.sleep(1)
                    continue

            print("Got a connection from %s" % str(addr))
            print('Socket connects %s and %s' % client_sock.getsockname(), client_sock.getpeername())

            if client_sock not in self.connection_list:
                self.connection_list.append(client_sock)

            self.msg_queues[client_sock] = queue.Queue()
            ClientThread(self, client_sock, addr)


class ClientThread(threading.Thread):

    def __init__(self, master, sock, address):
        # master --- Server_socket
        # sock --- client_socket (connection socket)
        # address --- client addr
        super().__init__(daemon=True, target=self.run)

        self.master = master
        self.sock = sock
        self.address = address
        self.buffer_size = 2048

        # имя пользователя
        self.login_user = ''
        self.inputs = []
        self.outpus = []

        # строка, получаемая от клиента
        self.__password = None

        self.start()

    def run(self):
        """ Главный метод для обработки клиентского потока, клиентского сокета """
        print('New thread started for connection from ' + str(self.address))
        self.inputs = [self.sock]
        self.outpus = [self.sock]
        while self.inputs:
            try:
                readable, writable, exceptional = select.select(self.inputs, self.outpus, self.inputs)
            except select.error:
                self.disconnect()
                break

            if self.sock in readable:
                try:
                    data = self.sock.recv(self.buffer_size)
                except socket.error:
                    self.disconnect()
                    break

                shutdown = self.process_recv_data(data)
                # отключаем, когда получаем пустые данные или при выходе
                if shutdown:
                    self.disconnect()
                    break

            if self.sock in writable:
                if not self.master.msg_queues[self.sock].empty():
                    data = self.master.msg_queues[self.sock].get()
                    try:
                        # отправляем прямо в сокет
                        self.sock.send(data)
                    except socket.error:
                        self.disconnect()
                        break

            if self.sock in exceptional:
                self.disconnect()

        # выход из главного цикла
        print('Closing {} thread, connection'.format(self.login_user))

    def __broadcast(self, msg):
        for client_sock, queue in self.master.msg_queues.items():
            pswd = self.master.get_password(client_sock)
            if pswd is not None:
                cipher_bytes = pyaes.AESModeOfOperationCTR(pswd.encode()).encrypt(msg)
                queue.put(cipher_bytes)
            else:
                print('No such a client.')

    def update_client_list(self):
        # Сказать всем пользователям, что список клиентов изменился
        print('update_client_list')
        # используется в GUI
        clients = ' '.join([user for user in self.master.login_dict])
        msg = make_protocol_msg(clients, 'ALL', '2', HOST, PORT, action='2')
        self.__broadcast(msg)

    def disconnect(self):
        """ Отсоединимся от сервера """
        print('Client {} has disconnected.'.format(self.login_user))
        # удалим связанную информацию с Сервером
        self.master.remove_user(self.login_user, self.sock)
        self.sock.close()
        self.update_client_list()

    def process_recv_data(self, data):
        # возвратим сигнал выключения
        if data is None or data == '':
            return True
        # data --- байты unicode, которые далее стают зашифрованными
        shutdown = False
        try:
            data = data.decode('utf-8')
        except UnicodeDecodeError:
            data = pyaes.AESModeOfOperationCTR(self.__password.encode()).decrypt(data).decode('utf-8')

        rec_dict = analyze_protocol_msg(data)
        print('Server receives: %s' % str(rec_dict))

        # проверяем первое соединение
        if rec_dict['affair'] == '0':

            public, private, modulus = self.__make_keys()
            mes = make_protocol_msg(str(public) + ' ' + str(modulus), rec_dict['src'], '1', HOST, PORT)
            self.sock.sendall(mes.encode())

            # получаем клиентский пароль
            meg = self.__decrypt(self.sock.recv(1024).decode('utf-8'), private, modulus)
            rec_dict = analyze_protocol_msg(meg)
            print('receive: %s' % str(rec_dict))
            self.__password = rec_dict['msg']

            print('ready for login')
            # отвечаем на клиентский успешный вход
            msg = make_protocol_msg('ready for login', rec_dict['src'], '2', HOST, PORT, action='0')
            cipher_bytes = pyaes.AESModeOfOperationCTR(self.__password.encode()).encrypt(msg)
            self.sock.sendall(cipher_bytes)

        # Обычное Подключение
        elif rec_dict['affair'] == '2' and self.__password is not None:
            # action поле доступно
            if 'action' in rec_dict:
                action = rec_dict['action']

                # вход пользователя
                if action == '0':
                    # получаем имя пользователя
                    self.login_user = rec_dict['msg']

                    if self.login_user in self.master.login_dict:
                        print('redundent login. Switch to new.')
                        self.master.remove_user(self.login_user, self.master.login_dict[self.login_user])
                    self.master.login_dict[self.login_user] = self.sock
                    self.master.set_password(self.sock, self.__password)

                    # говорим всем пользователям, что есть новый пользователь
                    self.update_client_list()

                # выход пользователя
                elif action == '3':
                    shutdown = True

                # one-to-one чат
                elif action[0] == '1':
                    to_user = action[2:]
                    from_user = self.login_user
                    if to_user in self.master.login_dict:
                        sock = self.master.login_dict[to_user]
                        msg = rec_dict['msg']
                        print('message from ' + from_user + ' sent to ' + to_user + ': ' + msg)
                        msg = make_protocol_msg(msg, to_user, 2, self.address[0], self.address[1],
                                                action='1 ' + from_user)
                        pswd = self.master.get_password(sock)
                        if pswd is not None:
                            cipher_bytes = pyaes.AESModeOfOperationCTR(pswd.encode()).encrypt(msg)
                            self.master.msg_queues[sock].put(cipher_bytes)
                        else:
                            print('cannot find pswd of user ' + to_user)

                # широковещательное сообщение
                elif action[0] == '2':
                    msg = rec_dict['msg']
                    print('message broadcase: ' + msg)

                    msg = make_protocol_msg(msg, 'ALL', 2, self.address[0], self.address[1],
                                            action='1 ' + self.login_user)
                    self.__broadcast(msg)

            else:
                print('no action available')
        return shutdown

    @staticmethod
    def extended_euclidean(a, b):
        # xa + yb = gcd(a, b)
        x, y, u, v = 0, 1, 1, 0
        while a != 0:
            q, r = b // a, b % a
            m, n = x - u * q, y - v * q
            b, a, x, y, u, v = a, r, u, v, m, n
        gcd = b
        return gcd, x, y

    # отрефакторить это ПРОСТО НЕОБХОДИМО
    def __make_keys(self):
        prime_P = 11
        prime_Q = 13
        n = prime_P * prime_Q
        phi = (prime_P - 1) * (prime_Q - 1)
        public_key = 7
        gcd, private_key, _ = self.extended_euclidean(public_key, phi)
        private_key += phi
        return public_key, private_key, n

    def __encrypt(self, meg, public_key, n):
        return ' '.join([str((ord(ch) ** public_key) % n) for ch in meg])

    @staticmethod
    def __decrypt(data, private_key, n):
        return ''.join([chr((int(x) ** private_key) % n) for x in data.split(' ')])


# Создаем сервер используя связку IP и порт
if __name__ == '__main__':
    server = Server(HOST, PORT)
