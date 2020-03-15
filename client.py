import queue
import select
import socket
import threading
import time

import pyaes
from gui import *
from myprotocol import *
from transliterate import translit


HOST = 'localhost'
PORT = 9876


class Client(threading.Thread):
    def __init__(self, host, port):
        # цель вызываемого объекта быть вызванным методом run()
        super().__init__(daemon=True, target=self.run)

        # получаем имя текущей машины и также сервер
        self.host = host
        self.port = port
        self.sock = None

        # используется в GUI
        # записываем в буфер: от клиента к серверу
        # ИЗМЕНИТЬ! хранит байты
        self.queue = queue.Queue()
        self.target = ''

        # имя пользователя (его логин)
        self.login_user = ''

        # используется I/O
        self.lock = threading.RLock()
        self.buffer_size = 2048

        self.dest_addr = str(self.host) + ':' + str(self.port)

        # объект байт, сгенерированный  __make_password
        self.__password = None

        self.connected = self.connect_to_server()
        if self.connected:
            self.gui = GUI(self)
            self.start()  # начало Client потока
            self.gui.start()  # начало GUI потока

    def __validate_host(hostname):
        return type(hostname) is str and len(hostname) != 0

    def __make_password():
        import random
        import string
        # генерирование 32-байтового пароля
        password = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
        return password.encode()

    def __encrypt(meg, public_key, n):
        return ' '.join([str((ord(ch) ** public_key) % n) for ch in meg])

    def str2int(*strs):
        return tuple([int(x) for x in strs])

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print('Inactive server, fail to connect.')
            return False

        # после подключения начинаем RSA шифрование
        # первый запрос к серверу с именем пользователя
        self.sock.sendall(make_protocol_msg(self.login_user, self.dest_addr, 0, self.host, self.port).encode())

        # получение публичного сообщения
        rev_dict = analyze_protocol_msg(self.sock.recv(2048).decode('utf-8'))
        print(rev_dict)

        if rev_dict['affair'] != '1':
            print('server not response affair 1')
            return False

        public, modulus = tuple(rev_dict['msg'].split(' '))
        public, modulus = self.str2int(public, modulus)

        if self.__validate_paten(public, modulus):
            # генерируем пароль клиента
            self.__password = self.__make_password()
            raw_msg = make_protocol_msg(self.__password.decode(), self.dest_addr, 1, self.host, self.port)
            # шифруем пароль, используя публичный ключ
            encr_msg = self.__encrypt(raw_msg, public, modulus)
            # отправляем зашифрованный пароль на сервер
            self.sock.sendall(encr_msg.encode())
        else:
            print('invalid paten')
            return False

        # получение сервером (OK)
        decr_bytes = pyaes.AESModeOfOperationCTR(self.__password).decrypt(self.sock.recv(2048))
        rec_dict = analyze_protocol_msg(decr_bytes.decode())
        print(rec_dict)
        if rec_dict['affair'] != '2':
            print('Server does not response 2')
            return False

        return True

    def encapsulate(self, msg, action=None):
        """ Сам протокол и шифрование """
        # сообщение - необработанная строка
        # возвращает: байтовое сообщение для отправки
        protocol = make_protocol_msg(msg, self.target, 2, self.host, self.port, action=action)
        encr_msg = pyaes.AESModeOfOperationCTR(self.__password).encrypt(protocol)
        return encr_msg

    def clear_queue(self):
        """ Очищаем очередь отправляя все сообщения """
        while not self.queue.empty():
            data = self.queue.get()
            self.send(data)

    # вызываемое GUI
    def notify_server(self, data, action):
        # данные - необработанная строка, данные при действиях логина и логаута
        print('client notifies server:', data, action)

        act = None
        if action == "logout":
            act = '3'
        elif action == "login":
            # когда юзер зашёл, GUI сообщает серверу введенное пользователем имя (username)
            self.login_user = data
            act = '0'

        en_data = self.encapsulate(translit(data, "ru", reversed=True), action=act)
        self.queue.put(en_data)

        if action == 'logout':
            self.clear_queue()
            self.sock.close()

    # вызываем после получения данных
    def process_recv_msg(self, data):
        decr_bytes = pyaes.AESModeOfOperationCTR(self.__password).decrypt(data)
        rec_dict = analyze_protocol_msg(decr_bytes.decode())
        print('Client receives: ' + str(rec_dict))
        # оповещаем всех пользователей о "новоприбывшем" пользователе
        if 'action' in rec_dict and rec_dict['action'] == '2':
            clients = rec_dict['msg'] + ' ALL'  # ВСЕ пользователи для широковещательных сообщений
            print('update client list: ' + clients)
            self.gui.main_window.update_login_list(clients.split(' '))
        else:
            # отображение сообщения в окне чата
            message = rec_dict['msg']
            sender = rec_dict.get('action', '1 unknown')[2:]
            time_tag = time.asctime(time.localtime(time.time()))
            message = sender + ">>>" + message
            message = message + ' ' * (60 - len(message)) + time_tag
            if len(message) > 0 and message[-1] != '\n':
                message += '\n'
            self.gui.display_message(message)

    def send(self, meg):
        # сообщение - зашифрованные байты
        with self.lock:
            try:
                self.sock.sendall(meg)
            except socket.error:
                self.sock.close()
                GUI.display_alert('client failed to send. Exit.')

    def close(self):
        self.sock.close()

    def run(self):
        inputs = [self.sock]
        outputs = [self.sock]
        while inputs:
            try:
                # три списка, содержащие коммуникационные каналы для мониторинга
                # список объектов, который должен быть проверен на считывание входящих данных
                # список объеков для получения исходящих данных где находится "комната" в буфере
                # список того, что может иметь ошибки, часто перемешанное с вводом и выводом
                # возвращает 3 новых списка, содержащих подмножества данных спиков, отправляемых на вход
                readable, writable, exceptional = select.select(inputs, outputs, inputs)
            except ValueError:
                print('Server error')
                GUI.display_alert('Server error. Exit.')
                self.sock.close()
                break

            if self.sock in readable:
                with self.lock:
                    try:
                        data = self.sock.recv(self.buffer_size)
                    except socket.error:
                        print('Socket error in reading')
                        GUI.display_alert('Socket error. Exit.')
                        self.sock.close()
                        break
                if len(data) is not 0:
                    self.process_recv_msg(data)
                else:
                    print('Server error')
                    GUI.display_alert('Server error. Exit.')
                    self.sock.close()
                    break

            if self.sock in writable:
                try:
                    if not self.queue.empty():
                        # Удаляем и возвращаем элемеент из очереди
                        data = self.queue.get()
                        self.send(data)
                        self.queue.task_done()
                    else:
                        # Приостановить исполнение вызывая поток на заданное кол-во времени
                        time.sleep(0.1)
                except socket.error:
                    print('Socket error in reading')
                    GUI.display_alert('Socket error. Exit.')
                    self.sock.close()
                    break

            if self.sock in exceptional:
                print('Server error')
                GUI.display_alert('Server error. Exit.')
                self.sock.close()
                break


# Создание нового клиента с помощью связки IP и порт
if __name__ == '__main__':
    Client(HOST, PORT)
