package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-units"
)

type ContainerStats struct {
	ID       string `json:"ID"`
	CPUPerc  string `json:"CPUPerc"`
	MemPerc  string `json:"MemPerc"`
	MemUsage string `json:"MemUsage"`
}

type StatsJSON struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	CPUStats    CPUStats    `json:"cpu_stats"`
	PreCPUStats CPUStats    `json:"precpu_stats"`
	MemoryStats MemoryStats `json:"memory_stats"`
}

type CPUStats struct {
	CPUUsage    CPUUsage `json:"cpu_usage"`
	SystemUsage uint64   `json:"system_cpu_usage"`
	OnlineCPUs  uint32   `json:"online_cpus"`
}

type CPUUsage struct {
	TotalUsage  uint64   `json:"total_usage"`
	PercpuUsage []uint64 `json:"percpu_usage"`
}

type MemoryStats struct {
	Usage uint64            `json:"usage"`
	Limit uint64            `json:"limit"`
	Stats map[string]uint64 `json:"stats"`
}

func getDockerClient() (*client.Client, error) {
	return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
}

func ExecuteContainerAction(containerID string, action string) error {
	ctx := context.Background()
	cli, err := getDockerClient()
	if err != nil {
		return err
	}
	defer cli.Close()

	switch action {
	case "start":
		return cli.ContainerStart(ctx, containerID, container.StartOptions{})
	case "stop":
		return cli.ContainerStop(ctx, containerID, container.StopOptions{})
	case "restart":
		return cli.ContainerRestart(ctx, containerID, container.StopOptions{})
	case "kill":
		return cli.ContainerKill(ctx, containerID, "KILL")
	case "pause":
		return cli.ContainerPause(ctx, containerID)
	case "unpause":
		return cli.ContainerUnpause(ctx, containerID)
	default:
		return fmt.Errorf("invalid action: %s", action)
	}
}

func GetContainerStats(containerID string) ([]ContainerStats, error) {
	ctx := context.Background()
	cli, err := getDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	var containers []types.Container
	if containerID != "" {
		containers = append(containers, types.Container{ID: containerID})
	} else {
		containers, err = cli.ContainerList(ctx, container.ListOptions{})
		if err != nil {
			return nil, err
		}
	}

	results := make([]ContainerStats, len(containers))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for idx, c := range containers {
		wg.Add(1)
		go func(c types.Container, i int) {
			defer wg.Done()

			stats, err := cli.ContainerStats(ctx, c.ID, true)
			if err != nil {
				return
			}
			defer stats.Body.Close()

			var statsJSON StatsJSON
			decoder := json.NewDecoder(stats.Body)

			if err := decoder.Decode(&statsJSON); err != nil {
				return
			}

			if statsJSON.PreCPUStats.CPUUsage.TotalUsage == 0 {
				var secondStats StatsJSON
				if err := decoder.Decode(&secondStats); err == nil {
					statsJSON = secondStats
				}
			}

			// Calculate CPU %
			var cpuPercent = 0.0
			cpuDelta := float64(statsJSON.CPUStats.CPUUsage.TotalUsage) - float64(statsJSON.PreCPUStats.CPUUsage.TotalUsage)
			systemDelta := float64(statsJSON.CPUStats.SystemUsage) - float64(statsJSON.PreCPUStats.SystemUsage)

			if systemDelta > 0.0 && cpuDelta > 0.0 {
				onlineCPUs := float64(statsJSON.CPUStats.OnlineCPUs)
				if onlineCPUs == 0.0 {
					onlineCPUs = float64(len(statsJSON.CPUStats.CPUUsage.PercpuUsage))
				}
				cpuPercent = (cpuDelta / systemDelta) * onlineCPUs * 100.0
			}

			// Calculate Mem % & Usage
			memUsage := float64(statsJSON.MemoryStats.Usage)
			if cache, ok := statsJSON.MemoryStats.Stats["cache"]; ok {
				memUsage = memUsage - float64(cache)
			} else if inactive, ok := statsJSON.MemoryStats.Stats["inactive_file"]; ok {
				memUsage = memUsage - float64(inactive)
			}

			memLimit := float64(statsJSON.MemoryStats.Limit)
			memPercent := 0.0
			if memLimit > 0 {
				memPercent = (memUsage / memLimit) * 100.0
			}

			statItem := ContainerStats{
				ID:       c.ID,
				CPUPerc:  fmt.Sprintf("%.2f%%", cpuPercent),
				MemPerc:  fmt.Sprintf("%.2f%%", memPercent),
				MemUsage: fmt.Sprintf("%s / %s", units.HumanSize(memUsage), units.HumanSize(memLimit)),
			}

			mu.Lock()
			results[i] = statItem
			mu.Unlock()
		}(c, idx)
	}

	wg.Wait()

	// Filter out uninitialized items (if any container stats failed)
	filteredResults := make([]ContainerStats, 0, len(results))
	for _, res := range results {
		if res.ID != "" {
			filteredResults = append(filteredResults, res)
		}
	}

	return filteredResults, nil
}

func GetContainers() ([]interface{}, error) {
	ctx := context.Background()
	cli, err := getDockerClient()
	if err != nil {
		return []interface{}{}, err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true, Size: true})
	if err != nil {
		return []interface{}{}, err
	}

	if len(containers) == 0 {
		return []interface{}{}, nil
	}

	// 2. Read Unraid Autostart File
	autoStartMap := make(map[string]bool)
	if content, err := os.ReadFile("/var/lib/docker/unraid-autostart"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				autoStartMap[parts[0]] = true
			}
		}
	}

	// 3. Inspect each container to match original output format (full JSON) and inject fields
	result := make([]interface{}, 0)

	for _, c := range containers {
		// We need full details
		jsonBytes, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}

		// Convert to map to inject fields
		var containerMap map[string]interface{}

		b, _ := json.Marshal(jsonBytes)
		json.Unmarshal(b, &containerMap)

		name := ""
		if n, ok := containerMap["Name"].(string); ok {
			name = strings.TrimPrefix(n, "/")
		}

		// Inject AutoStart
		if autoStartMap[name] {
			containerMap["AutoStart"] = true
		} else {
			containerMap["AutoStart"] = false
		}

		containerMap["SizeRw"] = c.SizeRw
		containerMap["SizeRootFs"] = c.SizeRootFs

		result = append(result, containerMap)
	}

	return result, nil
}
