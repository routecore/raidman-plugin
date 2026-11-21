package array

import (
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/domain"
)

func TestCalculateSpeeds(t *testing.T) {
	disk := func(name string, rb, wb, r, w int64) domain.ArrayDisk {
		return domain.ArrayDisk{Id: name, Name: name, ReadBytes: rb, WriteBytes: wb, NumReads: r, NumWrites: w}
	}
	flash := func(rb, wb, r, w int64) *domain.ArrayDisk {
		d := disk("flash", rb, wb, r, w)
		return &d
	}
	boot73 := func(rb, wb, r, w int64) *domain.ArrayDisk {
		d := disk("boot", rb, wb, r, w)
		d.Id = "boot"
		return &d
	}

	cases := []struct {
		name               string
		prev, curr         domain.ArrayStatus
		wantRead, wantWrit float64 // speeds of the checked device
		check              func(*domain.ArrayStatus) *domain.ArrayDisk
	}{
		{
			name:     "data disk bytes delta",
			prev:     domain.ArrayStatus{Disks: []domain.ArrayDisk{disk("disk1", 1000, 2000, 0, 0)}},
			curr:     domain.ArrayStatus{Disks: []domain.ArrayDisk{disk("disk1", 3000, 6000, 0, 0)}},
			wantRead: 1000, wantWrit: 2000,
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return &s.Disks[0] },
		},
		{
			name:     "data disk IO-count fallback",
			prev:     domain.ArrayStatus{Disks: []domain.ArrayDisk{disk("disk1", 0, 0, 10, 20)}},
			curr:     domain.ArrayStatus{Disks: []domain.ArrayDisk{disk("disk1", 0, 0, 12, 24)}},
			wantRead: 4096, wantWrit: 8192,
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return &s.Disks[0] },
		},
		{
			name:  "data disk counter reset",
			prev:  domain.ArrayStatus{Disks: []domain.ArrayDisk{disk("disk1", 9000, 9000, 0, 0)}},
			curr:  domain.ArrayStatus{Disks: []domain.ArrayDisk{disk("disk1", 100, 100, 0, 0)}},
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return &s.Disks[0] },
		},
		{
			name:     "flash boot bytes delta",
			prev:     domain.ArrayStatus{Boot: flash(1000, 1000, 0, 0)},
			curr:     domain.ArrayStatus{Boot: flash(1200, 1400, 0, 0)},
			wantRead: 100, wantWrit: 200,
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return s.Boot },
		},
		{
			name:  "flash boot counter reset (bytes)",
			prev:  domain.ArrayStatus{Boot: flash(1<<30, 1<<30, 0, 0)},
			curr:  domain.ArrayStatus{Boot: flash(4096, 4096, 0, 0)},
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return s.Boot },
		},
		{
			name:  "flash boot counter reset (IO fallback)",
			prev:  domain.ArrayStatus{Boot: flash(0, 0, 500, 500)},
			curr:  domain.ArrayStatus{Boot: flash(0, 0, 3, 4)},
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return s.Boot },
		},
		{
			name:     "7.3 boot slot",
			prev:     domain.ArrayStatus{Boot: boot73(0, 0, 10, 10)},
			curr:     domain.ArrayStatus{Boot: boot73(0, 0, 14, 10)},
			wantRead: 8192, wantWrit: 0,
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return s.Boot },
		},
		{
			name:  "7.3 boot slot counter reset",
			prev:  domain.ArrayStatus{Boot: boot73(5000, 5000, 0, 0)},
			curr:  domain.ArrayStatus{Boot: boot73(10, 10, 0, 0)},
			check: func(s *domain.ArrayStatus) *domain.ArrayDisk { return s.Boot },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			CalculateSpeeds(&c.curr, &c.prev, 2)
			d := c.check(&c.curr)
			if d.ReadSpeed < 0 || d.WriteSpeed < 0 {
				t.Fatalf("negative speed: read=%v write=%v", d.ReadSpeed, d.WriteSpeed)
			}
			if d.ReadSpeed != c.wantRead || d.WriteSpeed != c.wantWrit {
				t.Fatalf("read=%v write=%v, want %v/%v", d.ReadSpeed, d.WriteSpeed, c.wantRead, c.wantWrit)
			}
		})
	}
}

func TestCalculateSpeedsIgnoresUnknownDevicesAndZeroDelta(t *testing.T) {
	prev := domain.ArrayStatus{Disks: []domain.ArrayDisk{{Name: "disk1", ReadBytes: 1}}}
	curr := domain.ArrayStatus{Disks: []domain.ArrayDisk{{Name: "disk2", ReadBytes: 100}}, Boot: &domain.ArrayDisk{Id: "flash", ReadBytes: 5}}
	CalculateSpeeds(&curr, &prev, 1)
	if curr.Disks[0].ReadSpeed != 0 || curr.Boot.ReadSpeed != 0 {
		t.Fatalf("speeds without a previous sample: %+v %+v", curr.Disks[0], curr.Boot)
	}
	prev.Disks[0].Name = "disk2"
	CalculateSpeeds(&curr, &prev, 0)
	if curr.Disks[0].ReadSpeed != 0 {
		t.Fatal("zero delta must not compute a speed")
	}
}
