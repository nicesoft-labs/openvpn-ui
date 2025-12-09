package metrics

import "time"

// ClientEvent represents raw VPN client events.
type ClientEvent struct {
	ID int64

	EventType string
	EventTime time.Time

	VPNInstanceID string
	CommonName    string
	Username      string
	AuthMethod    string
	MFAUsed       bool
	MFAOK         bool

	TrustedIP     string
	TrustedPort   int
	UntrustedIP   string
	UntrustedPort int
	VPNIP         string
	VPNIPv6       string
	Proto         string
	Dev           string

	Cipher      string
	TLSVersion  string
	TLSCipher   string
	KeySizeBits int
	HMACDigest  string
	Compression string
	DCOEnabled  bool

	DeviceOS     string
	DeviceOSVer  string
	DeviceType   string
	DeviceVendor string
	DeviceModel  string
	DeviceID     string
	ClientApp    string
	ClientAppVer string

	GeoCountryCode string
	GeoCountryName string
	GeoRegion      string
	GeoCity        string
	GeoASN         string
	GeoOrg         string
	GeoLat         float64
	GeoLon         float64
	GeoTimezone    string
	GeoNetwork     string
	GeoFlag        string

	BytesReceived   uint64
	BytesSent       uint64
	PacketsReceived uint64
	PacketsSent     uint64
	DurationSec     int64
	Reconnects      int64

	DisconnectReason string
	EnvRaw           string

	CreatedAt time.Time
}

// Session represents normalized VPN sessions.
type Session struct {
	ID int64

	SessionUID    string
	VPNInstanceID string

	CommonName string
	Username   string
	Department string
	UserGroup  string
	UserRole   string

	TrustedIP     string
	TrustedPort   int
	UntrustedIP   string
	UntrustedPort int
	VPNIP         string
	VPNIPv6       string
	Proto         string
	Dev           string

	Cipher      string
	TLSVersion  string
	TLSCipher   string
	KeySizeBits int
	HMACDigest  string
	Compression string
	DCOEnabled  bool

	DeviceOS     string
	DeviceOSVer  string
	DeviceType   string
	DeviceVendor string
	DeviceModel  string
	DeviceID     string
	ClientApp    string
	ClientAppVer string

	GeoCountryCode string
	GeoCountryName string
	GeoRegion      string
	GeoCity        string
	GeoASN         string
	GeoOrg         string
	GeoLat         float64
	GeoLon         float64
	GeoTimezone    string
	GeoNetwork     string
	GeoFlag        string

	AuthMethod     string
	MFAUsed        bool
	MFAOK          bool
	IsSplitTunnel  bool
	IsAdminSession bool
	IsExternalUser bool

	ConnectTime    time.Time
	DisconnectTime *time.Time
	DurationSec    int64
	LastSeen       *time.Time

	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
	MaxBpsIn   uint64
	MaxBpsOut  uint64
	Reconnects int64

	Status           string
	DisconnectReason string

	CreatedAt time.Time
	UpdatedAt time.Time
}
