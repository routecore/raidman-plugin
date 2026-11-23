package domain

// XML Structures for parsing virsh dumpxml
type DomainXml struct {
	Description string   `xml:"description"`
	DeviceList  Devices  `xml:"devices"`
	Metadata    Metadata `xml:"metadata"`
}

type Metadata struct {
	VmTemplate VmTemplate `xml:"vmtemplate"`
}

type VmTemplate struct {
	Icon string `xml:"icon,attr"`
	Name string `xml:"name,attr"`
	Os   string `xml:"os,attr"`
}

type Devices struct {
	Disks      []Disk      `xml:"disk"`
	Interfaces []Interface `xml:"interface"`
	Graphics   []Graphics  `xml:"graphics"`
}

type Disk struct {
	Type   string     `xml:"type,attr"`
	Device string     `xml:"device,attr"`
	Source DiskSource `xml:"source"`
	Target DiskTarget `xml:"target"`
	Serial string     `xml:"serial"`
	Boot   *DiskBoot  `xml:"boot"`
}

type DiskSource struct {
	File string `xml:"file,attr"`
	Dev  string `xml:"dev,attr"` // for block devices
}

type DiskTarget struct {
	Dev string `xml:"dev,attr"`
	Bus string `xml:"bus,attr"`
}

type DiskBoot struct {
	Order int `xml:"order,attr"`
}

type Interface struct {
	Mac    MacAddress      `xml:"mac"`
	Source InterfaceSource `xml:"source"`
	Model  InterfaceModel  `xml:"model"`
}

type MacAddress struct {
	Address string `xml:"address,attr"`
}

type InterfaceSource struct {
	Bridge string `xml:"bridge,attr"`
	Dev    string `xml:"dev,attr"` // for direct/macvtap
}

type InterfaceModel struct {
	Type string `xml:"type,attr"`
}

type Graphics struct {
	Type     string `xml:"type,attr"`
	Port     int    `xml:"port,attr"`
	AutoPort string `xml:"autoport,attr"`
}

// JSON Output Structures
type VmDisk struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Bus       string `json:"bus"`
	Type      string `json:"type"`
	Serial    string `json:"serial"`
	BootOrder int    `json:"bootOrder"`
}

type VmInterface struct {
	Mac     string `json:"mac"`
	Model   string `json:"model"`
	Network string `json:"network"`
	// IpAddress is this NIC's first usable address (IPv4 preferred), "" if
	// unknown. Older plugins sent the first IPv4 found for any NIC of the
	// VM (host ARP table only) on every NIC.
	IpAddress string `json:"ipAddress"`
	// IpAddresses lists every usable address of this NIC (IPv4 first; no
	// loopback/link-local). Present (possibly empty) when
	// /api/health lists "vm.ips"; older plugins omit it.
	IpAddresses []string `json:"ipAddresses"`
}

// VmHostdev is a PCI or USB passthrough device (<devices><hostdev>).
type VmHostdev struct {
	Type string `json:"type"` // "pci" | "usb"
	// Kind is "gpu" (PCI class 0x03), "audio" (0x0403), "usb" (USB device or
	// PCI USB controller 0x0c03), or null.
	Kind   *string `json:"kind"`
	Name   *string `json:"name"`
	Vendor *string `json:"vendor"`
	// Address is the host PCI address ("0000:01:00.0"), the USB
	// "vendor:product" ids ("046d:c52b"), or "bus.device" ("001.004") for a
	// USB device given by bus address only.
	Address string `json:"address"`
}

type VmGraphics struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

type VmInfo struct {
	Name          string        `json:"name"`
	DomId         string        `json:"domId"`
	Uuid          string        `json:"uuid"`
	OsType        string        `json:"osType"`
	TemplateOs    string        `json:"templateOs"`
	DetailedState string        `json:"detailedState"`
	CpuTime       string        `json:"cpuTime"`
	Autostart     bool          `json:"autostart"`
	Memory        int64         `json:"memory"` // in Bytes
	Vcpus         int           `json:"vcpus"`
	Persistent    bool          `json:"persistent"`
	ManagedSave   string        `json:"managedSave"`
	SecurityModel string        `json:"securityModel"`
	SecurityDOI   string        `json:"securityDOI"`
	Description   string        `json:"description"`
	Icon          string        `json:"icon"`
	Disks         []VmDisk      `json:"disks"`
	Interfaces    []VmInterface `json:"interfaces"`
	Graphics      []VmGraphics  `json:"graphics"`
	// Hostdevs is [] when the domain has no passthrough devices and null when
	// the domain XML could not be read. Protocol-1 plugins omit it.
	Hostdevs []VmHostdev `json:"hostdevs"`
}

type AutostartRequest struct {
	Vm      string `json:"vm"`
	Enabled bool   `json:"enabled"`
}

type ArrayStatus struct {
	State string `json:"state"`
	// Parity Check Details
	ParityCheckStatus *ParityCheckStatus `json:"parityCheckStatus"`
	Parities          []ArrayDisk        `json:"parities"`
	Disks             []ArrayDisk        `json:"disks"`
	Caches            []ArrayDisk        `json:"caches"`
	Boot              *ArrayDisk         `json:"boot"`
	// BootDevices lists every boot slot (Unraid 7.3 internal boot pools can
	// have several). Optional; older plugin versions omit it.
	BootDevices []ArrayDisk `json:"bootDevices,omitempty"`
	Unassigned  []ArrayDisk `json:"unassigned"`
	// Health is the var.ini array health (nil when var.ini is unreadable).
	// Optional; older plugin versions omit it.
	Health *ArrayHealth `json:"health,omitempty"`
}

// ArrayHealth mirrors the app's ArrayHealth (field names and types) so it
// can be used as is. Values come straight from /var/local/emhttp/var.ini.
type ArrayHealth struct {
	ResyncPos int64 `json:"resyncPos"` // mdResyncPos (KiB)
	ResyncDb  int64 `json:"resyncDb"`  // mdResyncDb (KiB in the last sample)
	ResyncDt  int64 `json:"resyncDt"`  // mdResyncDt (seconds of the last sample)
	// ResyncAction is mdResyncAction: "check P", "check P Q", "recon P",
	// "recon D5", "clear"; null when empty.
	ResyncAction   *string `json:"resyncAction"`
	NumDisabled    int64   `json:"numDisabled"`
	NumInvalid     int64   `json:"numInvalid"`
	NumMissing     int64   `json:"numMissing"`
	FsState        *string `json:"fsState"`
	FsProgress     *string `json:"fsProgress"`
	FsCopyPercent  int64   `json:"fsCopyPercent"` // fsCopyPrcnt
	NumUnmountable int64   `json:"numUnmountable"`
	MoverActive    bool    `json:"moverActive"` // shareMoverActive
	SafeMode       bool    `json:"safeMode"`
	// ConfigValid is var.ini configValid as emhttp writes it: "yes", or why
	// the webGUI keeps Start disabled ("error", "invalid", "ineligible",
	// "nokeyserver", "withdrawn"). Null when var.ini has none.
	ConfigValid *string `json:"configValid"`
}

type ParityCheckStatus struct {
	Status          string `json:"status"` // "RUNNING", "PAUSED", "IDLE"
	Running         bool   `json:"running"`
	Paused          bool   `json:"paused"`
	Progress        string `json:"progress"` // "0.0" to "100.0"
	Speed           string `json:"speed"`    // e.g. "120.5 MB/s" or just number
	Duration        int64  `json:"duration"` // Seconds: now-sbSynced while running/paused, sbSynced2-sbSynced (last op) when idle
	Date            string `json:"date"`     // Unix Timestamp or Date String
	Errors          int64  `json:"errors"`
	ErrorsThisCheck int64  `json:"errorsThisCheck"` // Errors found during current check
	Pos             int64  `json:"pos"`
	Total           int64  `json:"total"`
	TimeRemaining   int64  `json:"timeRemaining"` // Estimated Seconds Remaining

	// Errors/ErrorsThisCheck come from sbSyncErrs. Correcting is mdResyncCorr == 1 while a check
	// runs (false when idle) and is always sent: its presence tells the app the errors are
	// sbSyncErrs-based (older plugins put the mdResyncCorr flag in Errors).
	Correcting bool `json:"correcting"`

	// Action is the raw mdResyncAction of the running or paused operation
	// ("check P", "recon D1", "clear", ...); omitted when idle. It tells a
	// rebuild or clear apart from a parity check.
	Action string `json:"action,omitempty"`
}

type ArrayDisk struct {
	Id         string  `json:"id"`
	Idx        int     `json:"idx"`
	Name       string  `json:"name"`
	Identifier string  `json:"identifier"`
	Device     string  `json:"device"`
	State      string  `json:"state"`
	Size       int64   `json:"size"`
	NumReads   int64   `json:"numReads"`
	NumWrites  int64   `json:"numWrites"`
	NumErrors  int64   `json:"numErrors"`
	ReadBytes  int64   `json:"readBytes,omitempty"`
	WriteBytes int64   `json:"writeBytes,omitempty"`
	ReadSpeed  float64 `json:"readSpeed"`
	WriteSpeed float64 `json:"writeSpeed"`
	Temp       int     `json:"temp"`
	FsSize     int64   `json:"fsSize"`
	FsUsed     int64   `json:"fsUsed"`
	FsFree     int64   `json:"fsFree"`
	FsType     string  `json:"fsType"`
	IsSpinning bool    `json:"isSpinning"`
	// Optional fields (added in protocol 2).
	Type         string `json:"type,omitempty"` // disks.ini slot type: Parity, Data, Cache, Flash, Boot
	FsStatus     string `json:"fsStatus,omitempty"`
	FsMountpoint string `json:"fsMountpoint,omitempty"`
}
