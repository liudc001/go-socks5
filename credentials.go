package socks5

// CredentialStore is used to support user/pass authentication
// 凭证存储，用于支持用户名密码认证模式
type CredentialStore interface {
	Valid(user, password string) bool // 判断用户名密码是否有效
}

// StaticCredentials enables using a map directly as a credential store
// 定义一个静态的用户名密码关系映射 map 对象
type StaticCredentials map[string]string

// 给用户名密码关系映射对象 增加方式，实现用户名密码校验
func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
