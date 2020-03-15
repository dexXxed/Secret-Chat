# Секретный чат

*"This is a private conversation."*

Секретный чат позволяет вам общаться абсолютно конфиденциально и безопасно.

Требования
------
Python 3.7

В файле ```requirements.txt``` имеются все необходимые зависимости.\
Выполните команду ```pip install -r requirements.txt``` для установки данных зависимостей.

Запуск
------
 1. В командной строке напишите `python server.py` для запуска сервера.
 2. В командной строке напишите `python client.py` для создания нового Клиента.
 3. Введите имя пользователя и нажмите "Login".
 4. Далее Вы можете переписываться с кем угодно на сервере.

Notice
------
1. All data between server and client is powerfully encrypted under the TLS/SSL protocol used by HTTPS. Your personal infomation would never be known by the third.
2. *Secret Chat* is built for secret chatting. Therefore, neither the server nor the client stores your data, including your user name, account, friend list and chatting history. 

Technical Details
------
![](./img/HTTPS.png)

License
-------
© Ziyuan Feng, 2017. Licensed under an [Apache-2](./LICENSE) license.
