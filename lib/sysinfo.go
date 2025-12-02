package lib

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"time"

	sigar "github.com/cloudfoundry/gosigar"
)

// FSUsage — сводка по файловой системе.
type FSUsage struct {
	Mount       string  `json:"mount"`
	FSType      string  `json:"fstype"`
	Device      string  `json:"device"`
	Total       uint64  `json:"total"`       // байты
	Used        uint64  `json:"used"`        // байты
	Free        uint64  `json:"free"`        // байты
	UsedPercent float64 `json:"usedPercent"` // 0..100
}

// SystemInfo содержит базовую информацию о системе.
type SystemInfo struct {
	Memory      sigar.Mem         `json:"memory"`
	Swap        sigar.Swap        `json:"swap"`
	Uptime      int               `json:"uptime"`   // сек
	UptimeS     string            `json:"uptimeS"`  // форматированно
	BootTime    time.Time         `json:"bootTime"` // приблизительно: now - uptime
	LoadAvg     sigar.LoadAverage `json:"loadAvg"`
	CPU         sigar.Cpu         `json:"cpu"`     // агрегированный CPU c тиками
	CPUList     sigar.CpuList     `json:"cpuList"` // per-CPU тики
	CPUCount    int               `json:"cpuCount"`
	Processes   int               `json:"processes"` // кол-во процессов
	FS          []FSUsage         `json:"fs"`        // список маунтов с usage
	Arch        string            `json:"arch"`
	Os          string            `json:"os"`
	Hostname    string            `json:"hostname"`
	CurrentTime time.Time         `json:"currentTime"`
}

// GetSystemInfo возвращает краткую сводку по системной нагрузке.
func GetSystemInfo() SystemInfo {
	s := SystemInfo{}

	// Аптайм
	var up sigar.Uptime
	if up.Get() == nil {
		s.Uptime = int(up.Length)
		s.UptimeS = up.Format()
	}

	// Load Average
	var avg sigar.LoadAverage
	if avg.Get() == nil {
		avg.One = formatFloat(avg.One)
		avg.Five = formatFloat(avg.Five)
		avg.Fifteen = formatFloat(avg.Fifteen)
		s.LoadAvg = avg
	}

	// Текущее время и "время загрузки" (приблизительно)
	s.CurrentTime = time.Now()
	if s.Uptime > 0 {
		s.BootTime = s.CurrentTime.Add(-time.Duration(s.Uptime) * time.Second)
	}

	// Память/свап
	var mem sigar.Mem
	if mem.Get() == nil {
		s.Memory = mem
	}
	var sw sigar.Swap
	if sw.Get() == nil {
		s.Swap = sw
	}

	// CPU (агрегированный и per-CPU)
	var cpu sigar.Cpu
	if cpu.Get() == nil {
		s.CPU = cpu
	}
	var cpus sigar.CpuList
	if cpus.Get() == nil {
		s.CPUList = cpus
		s.CPUCount = len(cpus.List)
	}

	// Процессы (только количество)
	var pl sigar.ProcList
	if pl.Get() == nil {
		s.Processes = len(pl.List)
	}

	// Файловые системы + их usage
	s.FS = collectFSUsage()

	// Базовая платформа
	s.Arch = runtime.GOARCH
	s.Os = runtime.GOOS
	if h, err := os.Hostname(); err == nil {
		s.Hostname = h
	}

	return s
}

func collectFSUsage() []FSUsage {
	out := make([]FSUsage, 0, 8)

	fsl := sigar.FileSystemList{}
	if err := fsl.Get(); err != nil {
		return out
	}

	for _, fs := range fsl.List {
		// fs.DirName — точка монтирования, fs.SysTypeName — тип (ext4, xfs, tmpfs, …)
		// Можно фильтровать псевдо-ФС, но оставим всё и аккуратно обработаем ошибки.
		var u sigar.FileSystemUsage
		if err := u.Get(fs.DirName); err != nil {
			continue
		}

		total := u.Total * 1024 // gosigar отдает значения в KiB
		used := u.Used * 1024
		free := u.Free * 1024
		usedPct := 0.0
		if total > 0 {
			usedPct = 100.0 * float64(used) / float64(total)
			usedPct = math.Min(100, math.Max(0, usedPct))
		}

		out = append(out, FSUsage{
			Mount:       fs.DirName,
			FSType:      fs.SysTypeName,
			Device:      fs.DevName,
			Total:       total,
			Used:        used,
			Free:        free,
			UsedPercent: round2(usedPct),
		})
	}

	return out
}

func formatFloat(f float64) float64 {
	formatted, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", f), 64)
	return formatted
}

func round2(f float64) float64 {
	return math.Round(f*100) / 100
}
