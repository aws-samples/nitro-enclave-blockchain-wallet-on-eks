package types

type EnclaveSystemMetrics struct {
	Timestamp            int64 `json:"Timestamp"`
	CPUConsumptionUser   int   `json:"CPUConsumptionUser"`
	CPUConsumptionSystem int   `json:"CPUConsumptionSystem"`
	MemoryUsed           int   `json:"MemoryUsed"`
	MemoryCached         int   `json:"MemoryCached"`
	// Min/Max for spike detection
	CPUUserMin    int `json:"CPUUserMin"`
	CPUUserMax    int `json:"CPUUserMax"`
	CPUSystemMin  int `json:"CPUSystemMin"`
	CPUSystemMax  int `json:"CPUSystemMax"`
	MemoryUsedMin int `json:"MemoryUsedMin"`
	MemoryUsedMax int `json:"MemoryUsedMax"`
}
