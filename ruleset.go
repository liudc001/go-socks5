package socks5

import (
	"golang.org/x/net/context"
)

// RuleSet is used to provide custom rules to allow or prohibit actions
// 规则校验接口，用于校验相应的访问规则
type RuleSet interface {
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

// PermitAll returns a RuleSet which allows all types of connections
// 全部放行
func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// PermitNone returns a RuleSet which disallows all types of connections
// 全部禁止
func PermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

// PermitCommand is an implementation of the RuleSet which
// enables filtering supported commands
type PermitCommand struct {
	EnableConnect   bool // 是否允许链接
	EnableBind      bool // 是否允许绑定
	EnableAssociate bool // 是否允许关联
}

func (p *PermitCommand) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	switch req.Command {
	case ConnectCommand:
		return ctx, p.EnableConnect
	case BindCommand:
		return ctx, p.EnableBind
	case AssociateCommand:
		return ctx, p.EnableAssociate
	}
	return ctx, false
}
