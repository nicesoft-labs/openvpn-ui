package metrics

// globalStore provides shared access for controllers.
var globalStore Store

// SetGlobalStore assigns store instance for global reads.
func SetGlobalStore(s Store) {
	globalStore = s
}

// GetGlobalStore returns globally configured store instance.
func GetGlobalStore() Store {
	return globalStore
}
