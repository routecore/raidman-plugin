package array

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/domain"
)

// nowFunc is the clock for parity durations (replaced in tests).
var nowFunc = time.Now

func GetArrayStatus() (*domain.ArrayStatus, error) {
	return getArrayStatusWithPaths(VarIniPath, DisksIniPath, DevsIniPath)
}

func getArrayStatusWithPaths(varIniPath, disksIniPath, devsIniPath string) (*domain.ArrayStatus, error) {
	// 1. Read /var/local/emhttp/var.ini for Global Status
	if _, err := os.Stat(varIniPath); os.IsNotExist(err) {
		// Fallback for dev/testing
		return &domain.ArrayStatus{
			State: "STARTED",
			ParityCheckStatus: &domain.ParityCheckStatus{
				Status:   "IDLE",
				Running:  false,
				Progress: "100.0",
				Date:     "1680000000",
				Duration: 3600,
				Speed:    "150.5 MB/s",
				Errors:   0,
			},
			Disks: []domain.ArrayDisk{
				{Id: "1", Name: "disk1", Device: "sdc", State: "DISK_OK", Size: 1000000000, NumReads: 789, NumWrites: 101, Idx: 1},
			},
			Parities: []domain.ArrayDisk{
				{Id: "0", Name: "parity", Device: "sdb", State: "DISK_OK", Size: 1000000000, NumReads: 123, NumWrites: 456, Idx: 0},
			},
			Caches: []domain.ArrayDisk{
				{Id: "cache", Name: "cache", Device: "nvme0n1", State: "DISK_OK", Size: 500000000, NumReads: 999, NumWrites: 888},
			},
			Boot: &domain.ArrayDisk{
				Id: "flash", Name: "flash", Device: "sdd", State: "DISK_OK", Size: 16000000, NumReads: 10, NumWrites: 20,
			},
		}, nil
	}

	status := &domain.ArrayStatus{
		State: "UNKNOWN",
		ParityCheckStatus: &domain.ParityCheckStatus{
			Status: "IDLE",
		},
		Parities:   []domain.ArrayDisk{},
		Disks:      []domain.ArrayDisk{},
		Caches:     []domain.ArrayDisk{},
		Unassigned: []domain.ArrayDisk{},
		Boot:       nil,
	}

	varMap, err := parseIniFile(varIniPath)
	if err == nil {
		if val, ok := varMap["mdState"]; ok {
			status.State = val
		}

		// Parity Check Details
		var total, pos, errs, dur int64
		var dTime, dBlocks int64

		// Helper for robust parsing
		parseInt := func(key string) int64 {
			val, ok := varMap[key]
			if !ok || val == "" {
				return 0
			}
			// Plain integer parsing
			i, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return 0
			}
			return i
		}

		total = parseInt("mdResyncSize")
		pos = parseInt("mdResyncPos")
		// sbSyncErrs is the sync error count (what the webGUI and the Unraid API report);
		// mdResyncCorr is only the 0/1 "correcting" flag of the running operation.
		errs = parseInt("sbSyncErrs")
		// NOTE: mdResyncDt is delta time between Unraid updates (~30s), NOT total elapsed.
		// Elapsed time comes from sbSynced (start of the current/last operation)
		// and sbSynced2 (its end, 0 while running), like unraid-api's
		// parity-check-status.ts, so it survives daemon restarts.
		synced, synced2 := parseInt("sbSynced"), parseInt("sbSynced2")
		if synced > 0 && synced2 >= synced {
			dur = synced2 - synced // idle: length of the last operation
		}
		// For speed calc
		dTime = parseInt("mdResyncDt")
		dBlocks = parseInt("mdResyncDb")

		status.ParityCheckStatus.Total = total
		status.ParityCheckStatus.Pos = pos
		status.ParityCheckStatus.Errors = errs
		status.ParityCheckStatus.Duration = dur // replaced below while running
		status.Health = healthFromVars(varMap, parseInt)

		// sbSynced is the timestamp of the last check.
		// If it's missing or empty, default to "0" to indicate "never".
		if val, ok := varMap["sbSynced"]; ok && val != "" {
			status.ParityCheckStatus.Date = val
		} else {
			status.ParityCheckStatus.Date = "0"
		}

		// Calculate Speed & Time Remaining (like unraid-api)
		var speedBytesPerSec float64

		if dTime > 0 && dBlocks > 0 {
			// Calculate speed from delta blocks / delta time

			speedBytesPerSec = (float64(dBlocks) * 1024.0) / float64(dTime)

			// Format speed string like Unraid (e.g. "150.5 MB/s")
			mbSpeed := speedBytesPerSec / (1024 * 1024)
			status.ParityCheckStatus.Speed = fmt.Sprintf("%.1f MB/s", mbSpeed)
		} else {
			// Fallback to string from var.ini if calculation not possible
			status.ParityCheckStatus.Speed = varMap["mdResyncSp"]

			// Try to parse fallback string for Time Remaining calc
			var speedVal float64
			var speedUnit string
			n, _ := fmt.Sscanf(status.ParityCheckStatus.Speed, "%f %s", &speedVal, &speedUnit)
			if n == 2 {
				switch speedUnit {
				case "KB/s":
					speedBytesPerSec = speedVal * 1024
				case "MB/s":
					speedBytesPerSec = speedVal * 1024 * 1024
				case "GB/s":
					speedBytesPerSec = speedVal * 1024 * 1024 * 1024
				default:
					speedBytesPerSec = speedVal
				}
			}
		}

		// Determine Status
		// Use mdResyncSize (total) > 0 to indicate valid check status
		// Fix: Match Unraid API logic, require mdResyncPos > 0 to consider it RUNNING/PAUSED.
		// If pos == 0, it is likely valid size but not currently checking.
		if total > 0 && pos > 0 && pos < total {
			status.ParityCheckStatus.Running = true

			// Correcting (writes parity) vs read-only check. emhttp's mdResyncAction is
			// "check P", "check P Q", "recon P" or "clear" and never says "corr"/"sync":
			// the correcting flag is mdResyncCorr.
			status.ParityCheckStatus.Correcting = parseInt("mdResyncCorr") == 1
			suffix := "CHECK"
			if status.ParityCheckStatus.Correcting {
				suffix = "SYNC"
			}

			// Running vs paused like the webGUI's Pause/Resume button
			// (ArrayOperation.page): mdResync != 0 while running, 0 while
			// paused. Kept identical to ReadParityState so the app never
			// offers an action the parity endpoints then refuse.
			if parseInt("mdResync") != 0 {
				status.ParityCheckStatus.Status = "RUNNING_" + suffix
			} else {
				status.ParityCheckStatus.Status = "PAUSED_" + suffix
			}

			if speedBytesPerSec > 0 {
				// Remaining blocks * 1024 / bytesPerSec
				remainingBlocks := total - pos
				remainingBytes := float64(remainingBlocks) * 1024.0
				status.ParityCheckStatus.TimeRemaining = int64(remainingBytes / speedBytesPerSec)
			}

			pct := float64(pos) / float64(total) * 100.0
			status.ParityCheckStatus.Progress = fmt.Sprintf("%.1f", pct)

			status.ParityCheckStatus.Action = varMap["mdResyncAction"]

			// sbSynced is set when the operation starts and sbSyncErrs
			// counts the errors of that operation.
			status.ParityCheckStatus.Duration = 0
			if synced > 0 {
				if elapsed := nowFunc().Unix() - synced; elapsed > 0 {
					status.ParityCheckStatus.Duration = elapsed
				}
			}
			status.ParityCheckStatus.ErrorsThisCheck = errs
		} else {
			status.ParityCheckStatus.Running = false
			status.ParityCheckStatus.Status = "IDLE"
			// If total > 0, we finished one? Or just idle.
			status.ParityCheckStatus.Progress = "100.0"
		}
	}

	parseStats := func(data map[string]string) (int64, int64, int64, int64, int64) {
		var r, w, e, rb, wb int64
		// Reads
		if v, ok := data["numReads"]; ok {
			fmt.Sscanf(v, "%d", &r)
		} else if v, ok := data["rdevNumReads"]; ok {
			fmt.Sscanf(v, "%d", &r)
		} else if v, ok := data["reads"]; ok {
			fmt.Sscanf(v, "%d", &r)
		}
		// Writes
		if v, ok := data["numWrites"]; ok {
			fmt.Sscanf(v, "%d", &w)
		} else if v, ok := data["rdevNumWrites"]; ok {
			fmt.Sscanf(v, "%d", &w)
		} else if v, ok := data["writes"]; ok {
			fmt.Sscanf(v, "%d", &w)
		}
		// Errors
		if v, ok := data["numErrors"]; ok {
			fmt.Sscanf(v, "%d", &e)
		} else if v, ok := data["rdevNumErrors"]; ok {
			fmt.Sscanf(v, "%d", &e)
		} else if v, ok := data["errors"]; ok {
			fmt.Sscanf(v, "%d", &e)
		}

		// Bytes (Sectors * 512)
		// Check for rsect/wsect (mdcmd standard) or read_bytes fallback
		var rs, ws int64
		if v, ok := data["rsect"]; ok {
			fmt.Sscanf(v, "%d", &rs)
			rb = rs * 512
		} else if v, ok := data["read_bytes"]; ok {
			// Some versions might have bytes directly?
			fmt.Sscanf(v, "%d", &rb)
		}
		if v, ok := data["wsect"]; ok {
			fmt.Sscanf(v, "%d", &ws)
			wb = ws * 512
		} else if v, ok := data["write_bytes"]; ok {
			fmt.Sscanf(v, "%d", &wb)
		}

		return r, w, e, rb, wb
	}

	// 2. Read /var/local/emhttp/disks.ini for Disk Details
	disksMap, err := parseIniSections(disksIniPath)
	var bootSlots, flashSlots []domain.ArrayDisk
	if err == nil {
		for _, section := range sortedSections(disksMap) {
			data := disksMap[section]
			if len(data) == 0 {
				continue
			}

			d := domain.ArrayDisk{
				Id:         section,
				Name:       data["name"],
				Identifier: data["id"],
				Device:     data["device"],
				State:      data["status"],
			}
			fmt.Sscanf(data["size"], "%d", &d.Size)
			fmt.Sscanf(data["idx"], "%d", &d.Idx)

			d.NumReads, d.NumWrites, d.NumErrors, d.ReadBytes, d.WriteBytes = parseStats(data)
			if d.Device != "" {
				if rb, wb := getDeviceStats(d.Device); rb > 0 || wb > 0 {
					d.ReadBytes = rb
					d.WriteBytes = wb
				}
			}

			// Temp can be "*" or number
			tempVal := data["temp"]
			if tempVal != "*" && tempVal != "" {
				fmt.Sscanf(tempVal, "%d", &d.Temp)
			}

			// Parse Filesystem and Spin info
			if val, ok := data["fsSize"]; ok {
				fmt.Sscanf(val, "%d", &d.FsSize)
			}
			if val, ok := data["fsUsed"]; ok {
				fmt.Sscanf(val, "%d", &d.FsUsed)
			}
			if val, ok := data["fsFree"]; ok {
				fmt.Sscanf(val, "%d", &d.FsFree)
			}
			if val, ok := data["fsType"]; ok {
				d.FsType = val
			} else {
				d.FsType = "auto"
			}
			if val, ok := data["spundown"]; ok {
				d.IsSpinning = val == "0"
			} else {
				d.IsSpinning = true
			}

			diskType := data["type"]
			d.Type = diskType
			d.FsStatus = data["fsStatus"]
			d.FsMountpoint = data["fsMountpoint"]

			switch diskType {
			case "Boot":
				// Unraid 7.3+ internal boot device(s).
				bootSlots = append(bootSlots, d)
			case "Flash":
				flashSlots = append(flashSlots, d)
			case "Parity":
				if d.Device != "" || d.State != "DISK_NP" {
					status.Parities = append(status.Parities, d)
				}
			case "Data":
				if d.Device != "" || d.State != "DISK_NP" {
					status.Disks = append(status.Disks, d)
				}
			case "Cache":
				if d.Device != "" && d.State != "DISK_NP" {
					status.Caches = append(status.Caches, d)
				}
			default:
				if d.Name != "" && d.Device != "" && d.State != "DISK_NP" {
					status.Caches = append(status.Caches, d)
				}
			}
		}
	}

	status.Boot, status.BootDevices = selectBoot(bootSlots, flashSlots)

	// 3. Read /var/local/emhttp/devs.ini for Unassigned Devices
	devsMap, err := parseIniSections(devsIniPath)
	if err == nil {
		for _, section := range sortedSections(devsMap) {
			data := devsMap[section]
			if len(data) == 0 {
				continue
			}

			d := domain.ArrayDisk{
				Id:         section,
				Name:       data["name"],
				Identifier: data["id"],
				Device:     data["device"],
				State:      "DISK_OK", // Usually Unassigned are OK if present
			}

			if d.Device == "" {
				continue
			}

			if val, ok := data["size"]; ok {
				fmt.Sscanf(val, "%d", &d.Size)
			}

			d.NumReads, d.NumWrites, d.NumErrors, d.ReadBytes, d.WriteBytes = parseStats(data)
			if d.Device != "" {
				if rb, wb := getDeviceStats(d.Device); rb > 0 || wb > 0 {
					d.ReadBytes = rb
					d.WriteBytes = wb
				}
			}

			if val, ok := data["temp"]; ok && val != "*" {
				fmt.Sscanf(val, "%d", &d.Temp)
			}

			// Parse Filesystem and Spin info for Unassigned Devices
			if val, ok := data["fsSize"]; ok {
				fmt.Sscanf(val, "%d", &d.FsSize)
			}
			if val, ok := data["fsUsed"]; ok {
				fmt.Sscanf(val, "%d", &d.FsUsed)
			}
			if val, ok := data["fsFree"]; ok {
				fmt.Sscanf(val, "%d", &d.FsFree)
			}
			if val, ok := data["fsType"]; ok {
				d.FsType = val
			} else {
				d.FsType = "auto"
			}
			if val, ok := data["spundown"]; ok {
				d.IsSpinning = val == "0"
			} else {
				d.IsSpinning = true
			}

			status.Unassigned = append(status.Unassigned, d)
		}
	}

	return status, nil
}

// healthFromVars builds the array health from var.ini (see the app's
// mapHealth and unraid-api's var.ini parser).
func healthFromVars(v map[string]string, parseInt func(string) int64) *domain.ArrayHealth {
	str := func(key string) *string {
		if val := v[key]; val != "" {
			return &val
		}
		return nil
	}
	return &domain.ArrayHealth{
		ResyncPos:      parseInt("mdResyncPos"),
		ResyncDb:       parseInt("mdResyncDb"),
		ResyncDt:       parseInt("mdResyncDt"),
		ResyncAction:   str("mdResyncAction"),
		NumDisabled:    parseInt("mdNumDisabled"),
		NumInvalid:     parseInt("mdNumInvalid"),
		NumMissing:     parseInt("mdNumMissing"),
		FsState:        str("fsState"),
		FsProgress:     str("fsProgress"),
		FsCopyPercent:  parseInt("fsCopyPrcnt"),
		NumUnmountable: parseInt("fsNumUnmountable"),
		MoverActive:    iniBool(v["shareMoverActive"]),
		SafeMode:       iniBool(v["safeMode"]),
		ConfigValid:    str("configValid"),
	}
}

// iniBool parses an emhttp yes/no (or true/false) value; anything else is false.
func iniBool(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "yes", "true":
		return true
	}
	return false
}

// selectBoot mirrors unraid-api core/modules/array/get-array-data.ts:
// internal boot slots (type "Boot", Unraid 7.3+) win over the USB flash; among
// candidates prefer the one mounted at /boot, then the first present device,
// then the first mounted one.
func selectBoot(bootSlots, flashSlots []domain.ArrayDisk) (*domain.ArrayDisk, []domain.ArrayDisk) {
	candidates := bootSlots
	if len(candidates) == 0 {
		for _, f := range flashSlots {
			if f.FsMountpoint == "" || f.FsMountpoint == "/boot" {
				candidates = append(candidates, f)
			}
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	pick := func(i int) (*domain.ArrayDisk, []domain.ArrayDisk) {
		b := candidates[i]
		return &b, candidates
	}
	for i, c := range candidates {
		if c.FsMountpoint == "/boot" {
			return pick(i)
		}
	}
	for i, c := range candidates {
		if c.State == "DISK_NP" || c.State == "DISK_NP_DSBL" || c.Device == "" {
			continue
		}
		return pick(i)
	}
	for i, c := range candidates {
		if c.FsStatus == "Mounted" {
			return pick(i)
		}
	}
	return pick(0)
}

// sortedSections returns ini sections ordered by slot index (then name) so
// output order is stable (disks.ini order: parity, disk1..N, pools, flash).
func sortedSections(m map[string]map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	idx := func(k string) int {
		n, err := strconv.Atoi(m[k]["idx"])
		if err != nil {
			return 1 << 30
		}
		return n
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := idx(keys[i]), idx(keys[j])
		if a != b {
			return a < b
		}
		return keys[i] < keys[j]
	})
	return keys
}

func getDeviceStats(device string) (int64, int64) {
	if device == "" {
		return 0, 0
	}
	path := fmt.Sprintf("/sys/block/%s/stat", device)
	file, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 7 {
			var rSects, wSects int64
			fmt.Sscanf(fields[2], "%d", &rSects)
			fmt.Sscanf(fields[6], "%d", &wSects)
			return rSects * 512, wSects * 512
		}
	}
	return 0, 0
}

func parseIniFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue // Skip comments and section headers for flat parser
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			result[key] = strings.Trim(val, "\"")
		}
	}
	return result, scanner.Err()
}

func parseIniSections(path string) (map[string]map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]map[string]string)
	var currentSection string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// Extract content between []
			rawSection := line[1 : len(line)-1]
			// Trim quotes if present (some Unraid INI files use ["section"])
			currentSection = strings.Trim(rawSection, "\"")
			result[currentSection] = make(map[string]string)
			continue
		}

		if currentSection != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				result[currentSection][key] = strings.Trim(val, "\"")
			}
		}
	}
	return result, scanner.Err()
}

// CalculateSpeeds updates the ReadSpeed/WriteSpeed fields based on difference from previous status
func CalculateSpeeds(curr *domain.ArrayStatus, prev *domain.ArrayStatus, deltaSeconds float64) {
	if deltaSeconds <= 0 {
		return
	}

	mapDisks := func(s *domain.ArrayStatus) map[string]domain.ArrayDisk {
		m := make(map[string]domain.ArrayDisk)
		for _, d := range s.Disks {
			key := d.Name
			if key == "" {
				key = d.Id
			}
			m[key] = d
		}
		for _, d := range s.Parities {
			key := d.Name
			if key == "" {
				key = d.Id
			}
			m[key] = d
		}
		for _, d := range s.Caches {
			key := d.Name
			if key == "" {
				key = d.Id
			}
			m[key] = d
		}
		for _, d := range s.Unassigned {
			key := d.Name
			if key == "" {
				key = d.Id
			}
			m[key] = d
		}
		if s.Boot != nil {
			m["boot"] = *s.Boot
		}
		return m
	}

	prevMap := mapDisks(prev)

	// Counters can go backwards (device re-enumerated after a USB reset,
	// stats cleared); such a sample yields no speed instead of a negative one.
	apply := func(d *domain.ArrayDisk, p domain.ArrayDisk) {
		// READS
		if d.ReadBytes > 0 && p.ReadBytes > 0 {
			if diff := float64(d.ReadBytes - p.ReadBytes); diff >= 0 {
				d.ReadSpeed = diff / deltaSeconds
			}
		} else if diff := float64(d.NumReads - p.NumReads); diff >= 0 {
			// Fallback: Estimate 4KB per IO
			d.ReadSpeed = (diff * 4096.0) / deltaSeconds
		}

		// WRITES
		if d.WriteBytes > 0 && p.WriteBytes > 0 {
			if diff := float64(d.WriteBytes - p.WriteBytes); diff >= 0 {
				d.WriteSpeed = diff / deltaSeconds
			}
		} else if diff := float64(d.NumWrites - p.NumWrites); diff >= 0 {
			d.WriteSpeed = (diff * 4096.0) / deltaSeconds
		}
	}

	updateSpeed := func(d *domain.ArrayDisk) {
		key := d.Name
		if key == "" {
			key = d.Id
		}
		if p, ok := prevMap[key]; ok {
			apply(d, p)
		}
	}

	for i := range curr.Disks {
		updateSpeed(&curr.Disks[i])
	}
	for i := range curr.Parities {
		updateSpeed(&curr.Parities[i])
	}
	for i := range curr.Caches {
		updateSpeed(&curr.Caches[i])
	}
	for i := range curr.Unassigned {
		updateSpeed(&curr.Unassigned[i])
	}
	if curr.Boot != nil {
		// Boot is keyed "boot" in prevMap whatever its name (flash or a 7.3 boot slot).
		if p, ok := prevMap["boot"]; ok {
			apply(curr.Boot, p)
		}
	}
}
