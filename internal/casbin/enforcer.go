package casbin

import (
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

var (
	enforcer *casbin.SyncedCachedEnforcer
	once     sync.Once
	mu       sync.RWMutex // protects enforcer and once
)

// InitEnforcer 初始化 Casbin Enforcer（单例模式）
func InitEnforcer(db *gorm.DB) (*casbin.SyncedCachedEnforcer, error) {
	mu.Lock()
	defer mu.Unlock()

	var err error
	once.Do(func() {
		// 创建 gorm-adapter
		adapter, adapterErr := gormadapter.NewAdapterByDB(db)
		if adapterErr != nil {
			err = adapterErr
			return
		}

		// 创建内嵌模型
		m := getModelConfig()

		// 创建 SyncedCachedEnforcer
		enforcer, err = casbin.NewSyncedCachedEnforcer(m, adapter)
		if err != nil {
			return
		}

		// 设置缓存过期时间（60分钟）
		enforcer.SetExpireTime(60 * 60)

		// 加载策略
		err = enforcer.LoadPolicy()
	})

	if err != nil {
		// 内部调用 reset（已经持有锁）
		resetUnlocked()
		return nil, err
	}

	return enforcer, nil
}

// resetUnlocked 内部重置函数（调用者必须持有 mu 锁）
func resetUnlocked() {
	enforcer = nil
	once = sync.Once{}
}

// Reset 重置 enforcer 实例（仅用于测试或错误恢复）
// WARNING: Reset() 不应在生产环境的并发场景中调用
// This function is NOT safe for use in production with concurrent InitEnforcer calls
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	resetUnlocked()
}

// GetEnforcer 获取全局 Enforcer 实例
// Panics if InitEnforcer() hasn't been called yet
func GetEnforcer() *casbin.SyncedCachedEnforcer {
	mu.RLock()
	defer mu.RUnlock()
	if enforcer == nil {
		panic("casbin: GetEnforcer called before InitEnforcer")
	}
	return enforcer
}

// getModelConfig 返回内嵌的 Casbin 模型配置
func getModelConfig() model.Model {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && r.act == p.act")
	return m
}
