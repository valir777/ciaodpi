эта программа реализует прокси-сервер с поддержкой TCP/UDP использующий шифрование AES для защиты передаваемых данных ; </br>
обфускацию трафика,ответы также разбиваются на части для отправки с случайными задержками,поддержка различных user-agent чтобы имитировать трафик реального браузера;</br>
так же используются несколько DNS-серверов для разрешения доменных имен. </br>

для запуска нужен golang и пакет golang.org/x/net/proxy </br>
файл list.txt должен лежать рядом с ciaodpi.go

запускаете командой sudo go run ciaodpi.go -local 127.0.0.1:443 и указываете прокси в браузере (я использую firefox указываю в http прокси и ставлю флаг так же для https) </br>
создавался для ютубчика,у меня лично работает,надеюсь у вас тоже
