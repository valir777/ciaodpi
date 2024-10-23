package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mathRand "math/rand"
	"net"
	"net/http"
	"bytes"
	"time"
	"bufio"
	"strings"
	"golang.org/x/net/proxy"
)

// Параметры задержек и фрагментов
var (
	minDelay     = 100 * time.Millisecond
	maxDelay     = 500 * time.Millisecond
	minChunkSize = 100
	maxChunkSize = 512
)

// Генерация случайного AES-ключа
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256-битный ключ для AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Создание HTTP-клиента с использованием SOCKS5 прокси
func newSOCKS5Client(proxyAddr string) (*http.Client, error) {
    dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
    if err != nil {
        return nil, err
    }

    transport := &http.Transport{
        Dial: dialer.Dial,
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   30 * time.Second,
    }

    return client, nil
}

// Глобальная переменная для хранения списка прокси
var proxyList []string

// Функция для загрузки прокси из онлайн файла
func loadProxyList(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ошибка при загрузке прокси: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	proxyList = strings.Split(string(body), "\n")
	for i := range proxyList {
		proxyList[i] = strings.TrimSpace(proxyList[i])
	}
	return nil
}

// Функция для получения случайного прокси
func getRandomProxy() string {
	mathRand.Seed(time.Now().UnixNano())
	return proxyList[mathRand.Intn(len(proxyList))]
}

// DNS-серверы
var dnsServers = []string{
    "8.8.8.8:53",    // Google DNS
    "8.8.4.4:53",    // Google DNS
    "1.1.1.1:53",    // Cloudflare DNS
    "1.0.0.1:53",    // Cloudflare DNS
    "208.67.222.222:53", // OpenDNS
    "208.67.220.220:53", // OpenDNS
}

	// Устанавливаем User-Agent, похожий на реальный браузер
	var userAgents = []string{
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.3",
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.3",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1 Ddg/16.",
	}
	

	// Функция для выбора случайного User Agent
	func getRandomUserAgent() string {
		mathRand.Seed(time.Now().UnixNano()) // Инициализация генератора случайных чисел
		return userAgents[mathRand.Intn(len(userAgents))] // Возвращает случайный элемент списка
	}

// Функция для разрешения доменных имен с использованием указанного DNS
func resolveDomain(domain string) (net.IP, error) {
	for _, dns := range dnsServers {
		ip, err := net.LookupIP(domain)
		if err == nil {
			return ip[0], nil
		}
		log.Printf("Ошибка при разрешении %s через %s: %v", domain, dns, err)
	}
	return nil, fmt.Errorf("не удалось разрешить домен %s", domain)
}

// Функция для чтения доменов из файла
func readSpecialDomains(filename string) ([]string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	domains := strings.Split(string(data), "\n")
	// Удаление пустых строк
	for i := 0; i < len(domains); i++ {
		domains[i] = strings.TrimSpace(domains[i])
		if domains[i] == "" {
			domains = append(domains[:i], domains[i+1:]...)
			i--
		}
	}
	return domains, nil
}

// AES шифрование данных
func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Создаем IV (инициализационный вектор)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// AES расшифровка данных
func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Функция для разделения данных на случайные части
func splitData(data []byte) [][]byte {
	var chunks [][]byte
	dataLen := len(data)

	// Разбиваем данные на случайные части
	for i := 0; i < dataLen; {
		chunkSize := mathRand.Intn(maxChunkSize-minChunkSize+1) + minChunkSize
		if i+chunkSize > dataLen {
			chunkSize = dataLen - i
		}
		chunks = append(chunks, data[i:i+chunkSize])
		i += chunkSize
	}

	return chunks
}

// Функция для адаптации параметров на основе состояния сети
func adaptParameters(networkLoad float64) {
	if networkLoad > 0.8 { // Высокая загрузка
		minDelay = 300 * time.Millisecond
		maxDelay = 1000 * time.Millisecond
		minChunkSize = 50
		maxChunkSize = 256
	} else if networkLoad > 0.5 { // Средняя загрузка
		minDelay = 200 * time.Millisecond
		maxDelay = 700 * time.Millisecond
		minChunkSize = 100
		maxChunkSize = 512
	} else { // Низкая загрузка
		minDelay = 100 * time.Millisecond
		maxDelay = 500 * time.Millisecond
		minChunkSize = 100
		maxChunkSize = 512
	}
}

// Функция для обфускации трафика с помощью случайных задержек
func sendWithAdaptiveDelay(conn net.Conn, data [][]byte) {
	for _, chunk := range data {
		delay := time.Duration(mathRand.Intn(int(maxDelay.Milliseconds()-minDelay.Milliseconds()))) * time.Millisecond + minDelay
		time.Sleep(delay)
		_, err := conn.Write(chunk)
		if err != nil {
			log.Printf("Ошибка при отправке данных: %v", err)
		}
	}
}

// Обработка HTTP-запросов с разделением данных и задержкой
func handleHTTPConnection(conn net.Conn, key []byte, specialDomains []string) { // Добавлен параметр specialDomains
	defer conn.Close()

	// Читаем HTTP-запрос
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Printf("Ошибка при чтении запроса: %v", err)
		return
	}
	log.Printf("Обрабатываем запрос: %s %s", req.Method, req.URL.String())

	// Выбираем случайный User Agent
		userAgent := getRandomUserAgent()
		req.Header.Set("User-Agent", userAgent) // Устанавливаем User Agent в запросе
		log.Printf("Используем User-Agent: %s", userAgent)

	// Логируем метод, URL, и заголовки
	log.Printf("Заголовки запроса: %+v", req.Header)



	// Сохраняем тело запроса для повторного использования
	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("Ошибка при чтении тела запроса: %v", err)
		return
	}
	req.Body.Close()

	// Логируем тело запроса (если не слишком большое)
	if len(reqBody) > 0 {
		log.Printf("Тело запроса: %s", string(reqBody))
	}

	// Проверяем, является ли домен из списка SpecialDomain
	isSpecialDomain := false
	for _, domain := range specialDomains {
		if strings.EqualFold(req.URL.Hostname(), domain) {
			isSpecialDomain = true
			break
		}
	}
	
	

	// Устанавливаем IP-адрес для хоста
	ip, err := resolveDomain(req.URL.Hostname())
	if err != nil {
		log.Printf("Ошибка разрешения домена: %v", err)
		return
	}

	// Используем IP для подключения, оборачиваем IPv6 адрес в квадратные скобки
	targetHost := fmt.Sprintf("[%s]:%d", ip.String(), 443)
	log.Printf("Устанавливаем туннель к %s", targetHost) // Логируем информацию о туннеле
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	handleTunnel(conn, targetHost)
	return


	// Проверяем, указана ли схема (http/https)
	if req.URL.Scheme == "" {
		if req.Method == "CONNECT" {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}

	// Если это CONNECT, устанавливаем туннель
	if req.Method == "CONNECT" {
		log.Printf("Устанавливаем туннель к %s", req.URL.Host) // Логируем информацию о CONNECT запросе
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		handleTunnel(conn, req.URL.Host) // Здесь мы обрабатываем туннель
		return
	}

		var client *http.Client // Объявляем переменную client

		// Если домен из списка то, обрабатываем его в первую очередь
		if isSpecialDomain {
			// Создаем новый HTTP-клиент с SOCKS5 прокси
			proxyAddr := getRandomProxy()
			client, err = newSOCKS5Client(proxyAddr)
			if err != nil {
				log.Printf("Ошибка создания клиента с прокси: %v", err)
				return
		}
		log.Printf("Используем прокси для домена: %s", req.URL.Hostname())
		} else {
			// Создаем обычный HTTP-клиент
		    client = &http.Client{}
		}

	// Создаем новый запрос, копируя информацию из исходного
	newReq := &http.Request{
		Method: req.Method,
		URL:    req.URL,
		Header: req.Header,
		Body:   ioutil.NopCloser(bufio.NewReader(bytes.NewReader(reqBody))), // Перезаписываем тело запроса
	}


	// Выполняем запрос
	resp, err := client.Do(newReq)
	if err != nil {
		log.Printf("Ошибка при выполнении запроса: %v", err)
		return
	}
	log.Printf("Ответ от %s: %d %s", req.URL.String(), resp.StatusCode, resp.Status)

	defer resp.Body.Close()

	// Читаем тело ответа
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Ошибка при чтении тела ответа: %v", err)
		return
	}

	// Разбиваем заголовки и тело ответа на части
	header := fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)
	for k, v := range resp.Header {
		for _, s := range v {
			header += fmt.Sprintf("%s: %s\r\n", k, s)
		}
	}
	header += "\r\n"

	headerChunks := splitData([]byte(header))
	bodyChunks := splitData(respBody)

	// Отправляем ответ частями с задержкой
	sendWithAdaptiveDelay(conn, append(headerChunks, bodyChunks...))
}

// Функция для обработки туннелей
func handleTunnel(conn net.Conn, host string) {
	defer conn.Close()

	// Создаем новое соединение с целевым хостом
	targetConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("Ошибка при подключении к %s: %v", host, err)
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer targetConn.Close()

	// Перенаправляем данные между клиентом и целевым хостом
	go func() {
		io.Copy(targetConn, conn) // Отправляем данные от клиента к серверу
	}()

	io.Copy(conn, targetConn) // Отправляем данные от сервера к клиенту
}

// Обработка UDP соединения с разделением данных и задержкой
func handleUDPConnection(conn *net.UDPConn, addr *net.UDPAddr, buffer []byte, key []byte) {
	log.Printf("Получены данные от %s", addr.String())

	// Расшифровываем данные
	decryptedData, err := decryptAES(buffer, key)
	if err != nil {
		log.Printf("Ошибка расшифровки: %v", err)
		return
	}

	log.Printf("Расшифрованные данные: %s", string(decryptedData))

	// Разделяем данные на части
	chunks := splitData(decryptedData)

	// Отправляем зашифрованные данные частями с задержкой
	for _, chunk := range chunks {
		encryptedResponse, err := encryptAES(chunk, key)
		if err != nil {
			log.Printf("Ошибка шифрования: %v", err)
			return
		}

		// Имитация случайной задержки между отправкой
		delay := time.Duration(mathRand.Intn(int(maxDelay.Milliseconds()-minDelay.Milliseconds()))) * time.Millisecond + minDelay
		time.Sleep(delay)

		// Отправляем зашифрованные части обратно клиенту
		_, err = conn.WriteToUDP(encryptedResponse, addr)
		if err != nil {
			log.Printf("Ошибка отправки данных: %v", err)
			return
		}
	}
}

// Основная функция
func main() {
	// Инициализация генератора случайных чисел
	mathRand.Seed(time.Now().UnixNano())

	// Чтение аргументов командной строки
	localAddr := flag.String("local", "127.0.0.1:443", "Локальный адрес для работы прокси (например, 127.0.0.1:443)")
	flag.Parse()

	// Чтение специального списка доменов из файла
	specialDomains, err := readSpecialDomains("list.txt")
	if err != nil {
		log.Fatalf("Ошибка при чтении доменов: %v", err)
	}

	//log.Printf("Загруженные специальные домены: %v", specialDomains)

	// Генерация AES-ключа для шифрования данных
	key, err := generateAESKey()
	if err != nil {
		log.Fatalf("Ошибка генерации AES ключа: %v", err)
	}
	log.Printf("AES ключ сгенерирован")

	// Устанавливаем прослушивание по указанному адресу для TCP
	tcpListener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		log.Fatalf("Ошибка при запуске TCP-сервера: %v", err)
	}
	defer tcpListener.Close()

	log.Printf("TCP сервер запущен на 127.0.0.1:443")

	// Устанавливаем прослушивание по указанному адресу для UDP
	addr, err := net.ResolveUDPAddr("udp", *localAddr)
	if err != nil {
		log.Fatalf("Ошибка создания UDP-адреса: %v", err)
	}

	// Создаем UDP-сервер
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Ошибка при запуске UDP-сервера: %v", err)
	}
	defer udpConn.Close()

	log.Printf("UDP сервер запущен на %s", *localAddr)

	// Обработка входящих соединений TCP
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				log.Printf("Ошибка при принятии соединения: %v", err)
				continue
			}
			go handleHTTPConnection(conn, key, specialDomains) // Передаем specialDomains еще обработка TCP соединений в отдельной горутине
		}
	}()

	// Обрабатываем входящие соединения UDP
	for {
		// Буфер для приема данных
		buffer := make([]byte, 4096)

		// Читаем данные от клиента
		n, clientAddr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Ошибка при чтении данных: %v", err)
			continue
		}

		log.Printf("Получены зашифрованные данные размером %d байт", n)

		// Обрабатываем соединение в отдельной горутине
		go handleUDPConnection(udpConn, clientAddr, buffer[:n], key)
	}

		// Загрузка прокси при старте
		err = loadProxyList("https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt")
		if err != nil {
			log.Fatalf("Ошибка при загрузке прокси: %v", err)
		}
		log.Printf("Прокси загружены: %v", proxyList)

		// Основной цикл
		for {
		// Проверяем на обновление прокси
		err = loadProxyList("https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt")
		if err != nil {
			log.Printf("Ошибка при обновлении прокси: %v", err)
		}
		time.Sleep(5 * time.Minute) // Обновляем каждые 5 минуту
	}
}