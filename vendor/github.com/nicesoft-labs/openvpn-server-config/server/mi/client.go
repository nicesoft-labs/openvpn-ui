package mi

import (
	"bufio"
	"net"
	"time"
)

// Client is used to connect to OpenVPN Management Interface
type Client struct {
	MINetwork string
	MIAddress string

	// Необязательные таймауты (по желанию)
	DialTimeout   time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	// Будущее: TLS / auth и т.п. можно добавить сюда
}

// NewClient initializes Management Interface client structure
func NewClient(network, address string) *Client {
	return &Client{
		MINetwork:   network, // Management Interface network (e.g., "tcp")
		MIAddress:   address, // Management Interface address (e.g., "127.0.0.1:2080")
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
}

// GetPid returns process id of OpenVPN server
func (c *Client) GetPid() (int64, error) {
	str, err := c.Execute("pid")
	if err != nil {
		return -1, err
	}
	return ParsePid(str)
}

// GetVersion returns version of OpenVPN server
func (c *Client) GetVersion() (*Version, error) {
	str, err := c.Execute("version")
	if err != nil {
		return nil, err
	}
	return ParseVersion(str)
}

// GetStatus returns list of connected clients and routing table.
// Сначала пробуем status 3 (более структурированный), при ошибке — status 2.
func (c *Client) GetStatus() (*Status, error) {
	str3, err := c.Execute("status 3")
	if err == nil {
		if st, perr := ParseStatus(str3); perr == nil {
			return st, nil
		}
	}
	// fallback
	str2, err2 := c.Execute("status 2")
	if err2 != nil {
		return nil, err2
	}
	return ParseStatus(str2)
}

// GetLoadStats returns number of connected clients and total number of network traffic
func (c *Client) GetLoadStats() (*LoadStats, error) {
	str, err := c.Execute("load-stats")
	if err != nil {
		return nil, err
	}
	return ParseStats(str)
}

// KillSession kills OpenVPN connection
func (c *Client) KillSession(cname string) (string, error) {
	str, err := c.Execute("kill " + cname)
	if err != nil {
		return "", err
	}
	return ParseKillSession(str)
}

// Signal sends signal to daemon
func (c *Client) Signal(signal string) error {
	str, err := c.Execute("signal " + signal)
	if err != nil {
		return err
	}
	return ParseSignal(str)
}

// RestartServer sends SIGUSR1 to gracefully restart the server
func (c *Client) RestartServer() error {
	return c.Signal("SIGUSR1")
}

// --------- Дополнительно/удобства ---------

// GetStateAll возвращает сырые строки состояния (state all)
func (c *Client) GetStateAll() ([]string, error) {
	str, err := c.Execute("state all")
	if err != nil {
		return nil, err
	}
	return ParseState(str)
}

// GetRemoteEntryCount возвращает количество remote-эндпоинтов
func (c *Client) GetRemoteEntryCount() (int, error) {
	str, err := c.Execute("remote-entry-count")
	if err != nil {
		return 0, err
	}
	return ParseRemoteEntryCount(str)
}

// GetRemoteEntriesAll возвращает сырые строки remote-entry-get all
func (c *Client) GetRemoteEntriesAll() ([]string, error) {
	str, err := c.Execute("remote-entry-get all")
	if err != nil {
		return nil, err
	}
	return ParseRemoteEntriesAll(str)
}

// ExecuteMulti — выполнить несколько команд за одно соединение.
// Возвращает ответы в том же порядке. Если любая команда падает — возвращаем ошибку.
func (c *Client) ExecuteMulti(cmds []string) ([]string, error) {
	out := make([]string, 0, len(cmds))
	err := c.withConn(func(conn net.Conn, r *bufio.Reader) error {
		// Прочитать welcome-баннер (может быть одна строка)
		if _, err := r.ReadString('\n'); err != nil {
			return err
		}
		for _, cmd := range cmds {
			if err := c.SendCommandWithTimeout(conn, cmd); err != nil {
				return err
			}
			resp, err := ReadResponse(r)
			if err != nil {
				return err
			}
			out = append(out, resp)
		}
		return nil
	})
	return out, err
}

// Execute connects to the OpenVPN server, sends command and reads response
func (c *Client) Execute(cmd string) (string, error) {
	var resp string
	err := c.withConn(func(conn net.Conn, r *bufio.Reader) error {
		// read welcome message (одна строка достаточно)
		if _, err := r.ReadString('\n'); err != nil {
			return err
		}
		if err := c.SendCommandWithTimeout(conn, cmd); err != nil {
			return err
		}
		tmp, err := ReadResponse(r)
		if err != nil {
			return err
		}
		resp = tmp
		return nil
	})
	return resp, err
}

// withConn — общая обёртка: установить соединение + буферизованный reader, вызвать fn, закрыть соединение.
func (c *Client) withConn(fn func(conn net.Conn, r *bufio.Reader) error) error {
	dialer := &net.Dialer{Timeout: c.DialTimeout}
	conn, err := dialer.Dial(c.MINetwork, c.MIAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	if c.ReadTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	}
	if c.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}

	reader := bufio.NewReader(conn)
	return fn(conn, reader)
}

// SendCommandWithTimeout — обёртка над SendCommand с установкой WriteDeadline.
func (c *Client) SendCommandWithTimeout(conn net.Conn, cmd string) error {
	if c.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}
	return SendCommand(conn, cmd)
}
