package nameserver

import (
	"github.com/miekg/dns"
	. "github.com/zettio/weave/common"
	"net"
	"sync"
)

const (
	RDNS_DOMAIN = "in-addr.arpa."
)

// +1 to also exclude a dot
var rdnsDomainLen = len(RDNS_DOMAIN) + 1

type Lookup interface {
	LookupName(name string) (net.IP, error)
	LookupInaddr(inaddr string) (string, error)
	LookupSrv(service string, proto string, name string) ([]SrvRecordValue, error)
}

type Zone interface {
	AddARecord(record ARecord) error
	AddSrvRecord(record SrvRecord) error
	DeleteARecord(ident string, ip net.IP) error
	DeleteSrvRecord(ident string, service string, port int, target string) error
	DeleteRecordsFor(ident string) error
	Lookup
}

type ARecord struct {
	Ident string
	Name  string
	IP    net.IP
}

type SrvRecordValue struct {
	TTL      int
	Priority int
	Weight   int
	Port     int
	Target   string
}

type SrvRecord struct {
	Ident   string
	Service string
	Proto   string
	Name    string
	value   SrvRecordValue
}

// Very simple data structure for now, with linear searching.
// TODO: make more sophisticated to improve performance
//       (including an identity lookup table to speedup DeleteRecordsFor).
type ZoneDb struct {
	mx      sync.RWMutex
	aRecs   []ARecord
	srvRecs []SrvRecord
}

type LookupError string

func (ops LookupError) Error() string {
	return "Unable to find " + string(ops)
}

type DuplicateError struct {
}

func (dup DuplicateError) Error() string {
	return "Tried to add a duplicate entry"
}

func (zone *ZoneDb) indexOf(match func(ARecord) bool) int {
	for i, r := range zone.aRecs {
		if match(r) {
			return i
		}
	}
	return -1
}

func (zone *ZoneDb) LookupName(name string) (net.IP, error) {
	zone.mx.RLock()
	defer zone.mx.RUnlock()
	for _, r := range zone.aRecs {
		if r.Name == name {
			return r.IP, nil
		}
	}
	return nil, LookupError(name)
}

func (zone *ZoneDb) LookupInaddr(inaddr string) (string, error) {
	if revIP := net.ParseIP(inaddr[:len(inaddr)-rdnsDomainLen]); revIP != nil {
		revIP4 := revIP.To4()
		ip := []byte{revIP4[3], revIP4[2], revIP4[1], revIP4[0]}
		Debug.Printf("[zonedb] Looking for address: %+v", ip)
		zone.mx.RLock()
		defer zone.mx.RUnlock()
		for _, r := range zone.aRecs {
			if r.IP.Equal(ip) {
				return r.Name, nil
			}
		}
		return "", LookupError(inaddr)
	} else {
		Warning.Printf("[zonedb] Asked to reverse lookup %s", inaddr)
		return "", LookupError(inaddr)
	}
}

func (zone *ZoneDb) LookupSrv(service string, proto string, name string) ([]SrvRecordValue, error) {
	return nil, nil
}

func (zone *ZoneDb) AddARecord(r ARecord) error {
	zone.mx.Lock()
	defer zone.mx.Unlock()
	fqdn := dns.Fqdn(r.Name)
	if index := zone.indexOf(
		func(lr ARecord) bool {
			return lr.Name == fqdn &&
				lr.IP.Equal(r.IP) &&
				lr.Ident == r.Ident
		}); index != -1 {
		return DuplicateError{}
	}
	zone.aRecs = append(zone.aRecs, ARecord{r.Ident, fqdn, r.IP})
	return nil
}

func (zone *ZoneDb) AddSrvRecord(r SrvRecord) error {
	return nil
}

func (zone *ZoneDb) DeleteARecord(ident string, ip net.IP) error {
	zone.mx.Lock()
	defer zone.mx.Unlock()
	if index := zone.indexOf(
		func(r ARecord) bool {
			return r.Ident == ident && r.IP.Equal(ip)
		}); index == -1 {
		return LookupError(ident)
	} else {
		zone.aRecs = append(zone.aRecs[:index], zone.aRecs[index+1:]...)
	}
	return nil
}

func (zone *ZoneDb) DeleteSrvRecord(ident string, service string, port int, target string) error {
	return nil
}

func (zone *ZoneDb) DeleteRecordsFor(ident string) error {
	zone.mx.Lock()
	defer zone.mx.Unlock()
	w := 0 // write index

	for _, r := range zone.aRecs {
		if r.Ident != ident {
			zone.aRecs[w] = r
			w++
		}
	}
	zone.aRecs = zone.aRecs[:w]

	for _, r := range zone.srvRecs {
		if r.Ident != ident {
			zone.srvRecs[w] = r
			w++
		}
	}
	zone.srvRecs = zone.srvRecs[:w]

	return nil
}
