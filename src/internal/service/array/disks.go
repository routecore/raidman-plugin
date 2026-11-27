package array

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// DiskState is one element of GET /api/disks/state. Every field comes from
// emhttp's state files (tmpfs); nothing here touches a disk, so polling it
// never wakes a spun-down drive.
type DiskState struct {
	Name   string `json:"name"`
	Device string `json:"device"`
	// Type is the disks.ini slot type: Parity, Data, Cache, Flash, Boot (7.3+
	// internal boot), ... ; devs.ini devices are reported as "Unassigned".
	Type     string `json:"type"`
	Spundown bool   `json:"spundown"`
	// Temp is null when emhttp reports "*" (spun down / unknown) or nothing.
	Temp   *int   `json:"temp"`
	Status string `json:"status"`
	// Rotational is null when emhttp does not report it.
	Rotational *bool `json:"rotational"`
}

// ParseTemp converts an emhttp temperature value ("30", "*", "") to a
// pointer (nil when unknown).
func ParseTemp(v string) *int {
	v = strings.TrimSpace(v)
	if v == "" || v == "*" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

func parseIniBool(v string) *bool {
	switch strings.TrimSpace(v) {
	case "1":
		t := true
		return &t
	case "0":
		f := false
		return &f
	}
	return nil
}

// GetDiskStates reads disks.ini (assigned slots, required) and devs.ini
// (unassigned devices, optional). Like the official API's slots parser, empty
// slots without id/device are skipped except type="Boot" slots.
func GetDiskStates() ([]DiskState, error) {
	sections, err := parseIniSections(DisksIniPath)
	if err != nil {
		return nil, fmt.Errorf("could not read disk state: %w", err)
	}
	out := []DiskState{}
	for _, s := range sortedSections(sections) {
		d := sections[s]
		if d["id"] == "" && d["device"] == "" && d["type"] != "Boot" {
			continue
		}
		name := d["name"]
		if name == "" {
			name = s
		}
		out = append(out, DiskState{
			Name:       name,
			Device:     d["device"],
			Type:       d["type"],
			Spundown:   d["spundown"] == "1",
			Temp:       ParseTemp(d["temp"]),
			Status:     d["status"],
			Rotational: parseIniBool(d["rotational"]),
		})
	}
	if devs, err := parseIniSections(DevsIniPath); err == nil {
		for _, s := range sortedSections(devs) {
			d := devs[s]
			if d["device"] == "" {
				continue
			}
			name := d["name"]
			if name == "" {
				name = s
			}
			status := d["status"]
			if status == "" {
				status = "DISK_OK"
			}
			out = append(out, DiskState{
				Name:       name,
				Device:     d["device"],
				Type:       "Unassigned",
				Spundown:   d["spundown"] == "1",
				Temp:       ParseTemp(d["temp"]),
				Status:     status,
				Rotational: parseIniBool(d["rotational"]),
			})
		}
	}
	return out, nil
}

// Spin implements POST /api/disks/spin: disk is an emhttp device name or
// "all", action "up" or "down". It returns nil only after emhttpd accepted
// the command.
func Spin(ctx context.Context, disk, action string) error {
	var up bool
	switch action {
	case "up":
		up = true
	case "down":
		up = false
	default:
		return badRequest("invalid action %q (want up or down)", action)
	}
	switch disk {
	case "":
		return badRequest("missing disk")
	case "all":
		return SpinAll(ctx, up)
	}
	return SpinDisk(ctx, disk, up)
}
