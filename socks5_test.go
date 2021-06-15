package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func TestSOCKS5_Connect(t *testing.T) {
	// Create a local listener
	// 开启本地tcp监听服务，端口号系统自动分配
	// [目标服务] 实际需要访问的服务器
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		// 本地监听并接收消息
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// 读取4个字节数据 至 buf数组
		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		fmt.Printf(">>> local listener Received cmd = %v\n", string(buf))

		// 判断读取的内容是否为 ping
		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}

		// [目标服务] 响应消息写入内容为 pong
		conn.Write([]byte("pong"))
	}()

	// ------------------------------------------------------------------------

	// [目标服务]获取tcp地址信息
	lAddr := l.Addr().(*net.TCPAddr)

	// [代理服务] Create a socks server
	// 身份认证配置
	creds := StaticCredentials{
		"foo": "bar", // username:password
	}
	// 定义身份认证器， 用户名密码认证
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	// 创建代理服务
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Start listening
	// [代理服务]开启监听 127.0.0.1:12365端口
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12365"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	// [客户端]创建客户端连接，准备连接代理服务
	conn, err := net.Dial("tcp", "127.0.0.1:12365")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Connect, auth and connect to local
	// 定义客户端向socks客户端发送消息内容
	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})                                     // VER 5
	req.Write([]byte{2, NoAuth, UserPassAuth})               // NMETHODS[2个长度], METHODS[0,2] : 2, 0 , 2; 不认证 或者 用户名密码认证
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'}) // userAuthVersion, len(username), username, len(password), password
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})              // 建立连接消息: VER,CMD,RSV,ATYP(addrType),DST.ADDR

	fmt.Printf(">>> wrap req data=%v\n", req.Bytes())

	fmt.Printf(">>> req lAddr.Port=%v\n", uint16(lAddr.Port))

	port := []byte{0, 0} // 端口2个字节
	// 实际端口号写入字节数组
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))

	req.Write(port) // DST.PORT

	// Send a ping
	req.Write([]byte("ping")) // DATA

	fmt.Printf(">>> send req all data=%v\n", req.Bytes())

	// Send all the bytes
	conn.Write(req.Bytes())

	// Verify response
	expected := []byte{
		socks5Version, // VER，协议
		UserPassAuth,  // METHOD， 认证方式
		1,             // userAuthVersion
		authSuccess,   // 认证结果为 成功
		5,             // ver
		0,             // CMD
		0,             // RSV 保留位
		1,             // ATYP
		127, 0, 0, 1,  // ip
		0, 0, // 端口
		'p', 'o', 'n', 'g',
	}
	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		t.Fatalf("err: %v", err)
	}

	fmt.Printf(">>> received resp data=%v\n", out)

	// Ignore the port
	out[12] = 0
	out[13] = 0

	fmt.Printf(">>> expected resp data=%v\n", expected)

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v", out)
	}
}
