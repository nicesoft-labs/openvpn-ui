package lib

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
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

// Health — общая оценка состояния.
type Health struct {
	Overall string   `json:"overall"` // "green" | "yellow" | "red"
	Reasons []string `json:"reasons"`
}

// MemView — удобный вид памяти для UI.
type MemView struct {
	Total       uint64  `json:"total"`
	ActualUsed  uint64  `json:"actualUsed"`
	ActualFree  uint64  `json:"actualFree"`
	ActualUsedP float64 `json:"actualUsedPercent"`
	NoSwap      bool    `json:"noSwap"`
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

	// Добавлено:
	Mem    MemView `json:"memView"` // удобный «вид» памяти
	Health Health  `json:"health"`  // оценка состояния
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

	// Load Average (с округлением до 2 знаков)
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

	// Удобный вид памяти
	s.Mem = makeMemView(s.Memory, s.Swap)

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

	// Файловые системы + их usage (с фильтрацией и агрегированием overlay)
	s.FS = collectFSUsageFiltered()

	// Базовая платформа
	s.Arch = runtime.GOARCH
	s.Os = runtime.GOOS
	if h, err := os.Hostname(); err == nil {
		s.Hostname = h
	}

	// Итоговая оценка здоровья
	s.Health = assessHealth(s)

	return s
}

// Собирает usage всех ФС без фильтрации.
func collectFSUsage() []FSUsage {
	out := make([]FSUsage, 0, 8)

	fsl := sigar.FileSystemList{}
	if err := fsl.Get(); err != nil {
		return out
	}

	for _, fs := range fsl.List {
		// fs.DirName — точка монтирования, fs.SysTypeName — тип (ext4, xfs, tmpfs, …)
		var u sigar.FileSystemUsage
		if err := u.Get(fs.DirName); err != nil {
			continue
		}

		// gosigar возвращает значения в KiB
		total := u.Total * 1024
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

// Фильтрует «шумные» ФС и схлопывает docker overlay.
func collectFSUsageFiltered() []FSUsage {
	raw := collectFSUsage()

	// Псевдо-ФС скрываем, tmpfs показываем выборочно.
	skip := map[string]bool{
		"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
		"tmpfs": false, // покажем только /tmp, /run, /dev/shm
		"cgroup": true, "cgroup2": true, "pstore": true, "bpf": true,
		"autofs": true, "hugetlbfs": true, "mqueue": true, "debugfs": true,
		"tracefs": true, "nsfs": true, "securityfs": true, "configfs": true,
		"fusectl": true, "binfmt_misc": true,
	}

	out := make([]FSUsage, 0, len(raw))
	for _, fs := range raw {
		if skip[fs.FSType] {
			continue
		}
		if fs.FSType == "tmpfs" {
			if !(fs.Mount == "/tmp" || fs.Mount == "/run" || fs.Mount == "/dev/shm") {
				continue
			}
		}
		out = append(out, fs)
	}

	// Схлопываем дубликаты overlay от Docker в один понятный блок.
	out = aggregateOverlay(out)

	return out
}

// Агрегирует overlay-маунты Docker в один элемент /var/lib/docker (overlay).
func aggregateOverlay(fs []FSUsage) []FSUsage {
	var overlays []FSUsage
	var nonOverlay []FSUsage
	for _, f := range fs {
		if f.FSType == "overlay" || f.Device == "overlay" {
			overlays = append(overlays, f)
		} else {
			nonOverlay = append(nonOverlay, f)
		}
	}
	if len(overlays) == 0 {
		return fs
	}
	// Выберем репрезентативный overlay.
	rep := overlays[0]
	for _, o := range overlays {
		if strings.HasPrefix(o.Mount, "/var/lib/docker/overlay2") {
			rep = o
			break
		}
	}
	rep.Mount = "/var/lib/docker (overlay)"
	return append(nonOverlay, rep)
}

// Удобный вид памяти (actual used/free, проценты, признак swap).
func makeMemView(m sigar.Mem, sw sigar.Swap) MemView {
	mv := MemView{
		Total:      m.Total,
		ActualUsed: m.ActualUsed,
		ActualFree: m.ActualFree,
		NoSwap:     sw.Total == 0,
	}
	if m.Total > 0 {
		mv.ActualUsedP = round2(100.0 * float64(m.ActualUsed) / float64(m.Total))
	}
	return mv
}

// Простая оценка здоровья на основе RAM, swap, load и дисков.
func assessHealth(s SystemInfo) Health {
	h := Health{Overall: "green"}

	add := func(msg string, sev string) {
		h.Reasons = append(h.Reasons, msg)
		switch sev {
		case "red":
			h.Overall = "red"
		case "yellow":
			if h.Overall == "green" {
				h.Overall = "yellow"
			}
		}
	}

	// RAM (actual used)
	if s.Mem.ActualUsedP > 95 {
		add(fmt.Sprintf("RAM high: %.0f%%", s.Mem.ActualUsedP), "red")
	} else if s.Mem.ActualUsedP > 85 {
		add(fmt.Sprintf("RAM high: %.0f%%", s.Mem.ActualUsedP), "yellow")
	}

	// Swap
	if s.Mem.NoSwap {
		add("Swap disabled", "yellow")
	}

	// CPU: load 5m vs число ядер (очень упрощённо)
	if s.CPUCount > 0 {
		if s.LoadAvg.Five > float64(s.CPUCount)*2.0 {
			add("CPU load 5m very high", "red")
		} else if s.LoadAvg.Five > float64(s.CPUCount)*1.0 {
			add("CPU load 5m high", "yellow")
		}
	}

	// Диски: предупреждаем по реальным ФС (не tmpfs)
	for _, f := range s.FS {
		if f.FSType == "tmpfs" {
			continue
		}
		if f.UsedPercent >= 90 {
			add(fmt.Sprintf("Disk nearly full: %s (%.0f%%)", f.Mount, f.UsedPercent), "red")
		} else if f.UsedPercent >= 80 {
			add(fmt.Sprintf("Disk getting full: %s (%.0f%%)", f.Mount, f.UsedPercent), "yellow")
		}
	}

	return h
}

func formatFloat(f float64) float64 {
	formatted, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", f), 64)
	return formatted
}

func round2(f float64) float64 {
	return math.Round(f*100) / 100
}
