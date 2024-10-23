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

	// Разбиваем данные на случайные части (размер от 50 до 200 байт)
	for i := 0; i < dataLen; {
		chunkSize := mathRand.Intn(151) + 50 // Размер фрагмента от 50 до 200 байт
		if i+chunkSize > dataLen {
			chunkSize = dataLen - i
		}
		chunks = append(chunks, data[i:i+chunkSize])
		i += chunkSize
	}

	return chunks
}

// Обработка HTTP-запросов с разделением данных и задержкой
func handleHTTPConnection(conn net.Conn, key []byte) {
	defer conn.Close()

	// Читаем HTTP-запрос
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Printf("Ошибка при чтении запроса: %v", err)
		return
	}
	log.Printf("Обрабатываем запрос: %s %s", req.Method, req.URL.String())

	// Сохраняем тело запроса для повторного использования
	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Println("Ошибка при чтении тела запроса:", err)
		return
	}
	req.Body.Close()


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
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		handleTunnel(conn, req.URL.Host) // Здесь мы обрабатываем туннель
		return
	}


	// Создаем новый запрос, копируя информацию из исходного
	newReq := &http.Request{
		Method: req.Method,
		URL:    req.URL,
		Header: req.Header,
		Body:   ioutil.NopCloser(bufio.NewReader(bytes.NewReader(reqBody))), // Перезаписываем тело запроса
	}

	// Обрабатываем HTTP-запрос
	client := &http.Client{}

	// Выполняем запрос
	resp, err := client.Do(newReq)
	if err != nil {
		log.Printf("Ошибка при выполнении запроса: %v", err)
		return
	}
	log.Printf("Ответ от %s: %d %s", req.URL.String(), resp.StatusCode, resp.Status)
	
	defer resp.Body.Close()

	// Формируем заголовки ответа
	header := fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)
	for k, v := range resp.Header {
		for _, s := range v {
			header += fmt.Sprintf("%s: %s\r\n", k, s)
		}
	}
	header += "\r\n"

	// Отправляем ответ клиенту
	conn.Write([]byte(header))
	io.Copy(conn, resp.Body)

	// Читаем тело ответа
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Ошибка при чтении тела ответа:", err)
		return
	}

	// Разбиваем данные на части
	chunks := splitData([]byte(header))
	bodyChunks := splitData(respBody)

	// Отправляем ответ частями с задержкой
	for _, chunk := range append(chunks, bodyChunks...) {
		time.Sleep(time.Duration(mathRand.Intn(200)) * time.Millisecond) // Имитация задержки
		conn.Write(chunk)
	}
}

	// Функция для обработки туннелей
	func handleTunnel(conn net.Conn, host string) {
		defer conn.Close()

		// Создаем новое соединение с целевым хостом
		targetConn, err := net.Dial("tcp", host)
		if err != nil {
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
		time.Sleep(time.Duration(mathRand.Intn(200)) * time.Millisecond)

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
			go handleHTTPConnection(conn, key) // Обработка TCP соединений в отдельной горутине
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
}
//made with love for community github.com/valir777