package main

// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/dns"
	"github.com/jeessy2/ddns-go/v6/util"
)

var (
	ddnsInstances      = make(map[int]*ddnsWrapper)
	ddnsInstancesMutex sync.RWMutex
	nextInstanceID     = 1
)

type ddnsWrapper struct {
	dnsProvider dns.DNS
	dnsConf     *config.DnsConfig
	ipv4cache   *util.IpCache
	ipv6cache   *util.IpCache
	stopCh      chan struct{}
	isRunning   bool
	lastResult  string
}

func main() {}

//export DdnsInit
func DdnsInit() {
}

//export DdnsCreateInstance
func DdnsCreateInstance(
	dnsProvider *C.char, // DNS 提供商名称，如 "cloudflare", "alidns" 等
) C.int {
	if dnsProvider == nil {
		return -1
	}

	ddnsInstancesMutex.Lock()
	defer ddnsInstancesMutex.Unlock()

	providerName := C.GoString(dnsProvider)

	// 根据提供商名称创建对应的 DNS 实例
	var dnsSelected dns.DNS
	switch providerName {
	case "alidns":
		dnsSelected = &dns.Alidns{}
	case "aliesa":
		dnsSelected = &dns.Aliesa{}
	case "tencentcloud":
		dnsSelected = &dns.TencentCloud{}
	case "trafficroute":
		dnsSelected = &dns.TrafficRoute{}
	case "dnspod":
		dnsSelected = &dns.Dnspod{}
	case "dnsla":
		dnsSelected = &dns.Dnsla{}
	case "cloudflare":
		dnsSelected = &dns.Cloudflare{}
	case "huaweicloud":
		dnsSelected = &dns.Huaweicloud{}
	case "callback":
		dnsSelected = &dns.Callback{}
	case "baiducloud":
		dnsSelected = &dns.BaiduCloud{}
	case "porkbun":
		dnsSelected = &dns.Porkbun{}
	case "godaddy":
		dnsSelected = &dns.GoDaddyDNS{}
	case "namecheap":
		dnsSelected = &dns.NameCheap{}
	case "namesilo":
		dnsSelected = &dns.NameSilo{}
	case "vercel":
		dnsSelected = &dns.Vercel{}
	case "dynadot":
		dnsSelected = &dns.Dynadot{}
	case "dynv6":
		dnsSelected = &dns.Dynv6{}
	case "spaceship":
		dnsSelected = &dns.Spaceship{}
	case "nowcn":
		dnsSelected = &dns.Nowcn{}
	case "eranet":
		dnsSelected = &dns.Eranet{}
	case "gcore":
		dnsSelected = &dns.Gcore{}
	case "edgeone":
		dnsSelected = &dns.EdgeOne{}
	case "nsone":
		dnsSelected = &dns.NSOne{}
	case "name_com":
		dnsSelected = &dns.NameCom{}
	default:
		return -2 // 不支持的提供商
	}

	wrapper := &ddnsWrapper{
		dnsProvider: dnsSelected,
		dnsConf:     &config.DnsConfig{},
		ipv4cache:   &util.IpCache{},
		ipv6cache:   &util.IpCache{},
		stopCh:      make(chan struct{}),
		isRunning:   false,
	}

	instanceID := nextInstanceID
	nextInstanceID++
	ddnsInstances[instanceID] = wrapper

	return C.int(instanceID)
}

//export DdnsSetProviderName
func DdnsSetProviderName(
	instanceID C.int,
	providerName *C.char,
) C.int {
	if providerName == nil {
		return -1
	}

	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	wrapper.dnsConf.DNS.Name = C.GoString(providerName)

	return 0
}

//export DdnsSetCredentials
func DdnsSetCredentials(
	instanceID C.int,
	id *C.char,
	secret *C.char,
) C.int {
	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	if id != nil {
		wrapper.dnsConf.DNS.ID = C.GoString(id)
	}
	if secret != nil {
		wrapper.dnsConf.DNS.Secret = C.GoString(secret)
	}

	return 0
}

//export DdnsAddDomain
func DdnsAddDomain(
	instanceID C.int,
	domainName *C.char,
	subDomain *C.char,
	ipv4Enabled C.int,
	ipv6Enabled C.int,
) C.int {
	if domainName == nil {
		return -1
	}

	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	domainStr := C.GoString(domainName)
	var fullDomain string
	if subDomain != nil {
		fullDomain = C.GoString(subDomain) + "." + domainStr
	} else {
		fullDomain = domainStr
	}

	if ipv4Enabled != 0 {
		wrapper.dnsConf.Ipv4.Enable = true
		wrapper.dnsConf.Ipv4.Domains = append(wrapper.dnsConf.Ipv4.Domains, fullDomain)
	}
	if ipv6Enabled != 0 {
		wrapper.dnsConf.Ipv6.Enable = true
		wrapper.dnsConf.Ipv6.Domains = append(wrapper.dnsConf.Ipv6.Domains, fullDomain)
	}

	return 0
}

//export DdnsRemoveDomain
func DdnsRemoveDomain(
	instanceID C.int,
	domainName *C.char,
	subDomain *C.char,
) C.int {
	if domainName == nil {
		return -1
	}

	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	domainStr := C.GoString(domainName)
	var fullDomain string
	if subDomain != nil {
		fullDomain = C.GoString(subDomain) + "." + domainStr
	} else {
		fullDomain = domainStr
	}

	newIpv4Domains := make([]string, 0)
	for _, d := range wrapper.dnsConf.Ipv4.Domains {
		if d != fullDomain {
			newIpv4Domains = append(newIpv4Domains, d)
		}
	}
	wrapper.dnsConf.Ipv4.Domains = newIpv4Domains

	newIpv6Domains := make([]string, 0)
	for _, d := range wrapper.dnsConf.Ipv6.Domains {
		if d != fullDomain {
			newIpv6Domains = append(newIpv6Domains, d)
		}
	}
	wrapper.dnsConf.Ipv6.Domains = newIpv6Domains

	return 0
}

//export DdnsClearDomains
func DdnsClearDomains(instanceID C.int) C.int {
	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	wrapper.dnsConf.Ipv4.Domains = make([]string, 0)
	wrapper.dnsConf.Ipv6.Domains = make([]string, 0)

	return 0
}

//export DdnsSetIPv4Address
func DdnsSetIPv4Address(
	instanceID C.int,
	ipv4Addr *C.char,
) C.int {
	if ipv4Addr == nil {
		return -1
	}

	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	addr := C.GoString(ipv4Addr)
	wrapper.dnsConf.Ipv4.URL = addr

	return 0
}

//export DdnsSetIPv4GetType
func DdnsSetIPv4GetType(
	instanceID C.int,
	getType *C.char,
) C.int {
	if getType == nil {
		return -1
	}

	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	wrapper.dnsConf.Ipv4.GetType = C.GoString(getType)

	return 0
}

//export DdnsSetIPv6Address
func DdnsSetIPv6Address(
	instanceID C.int,
	ipv6Addr *C.char,
) C.int {
	if ipv6Addr == nil {
		return -1
	}

	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	addr := C.GoString(ipv6Addr)
	wrapper.dnsConf.Ipv6.URL = addr

	return 0
}

//export DdnsSetIPv6GetType
func DdnsSetIPv6GetType(
	instanceID C.int,
	getType *C.char,
) C.int {
	if getType == nil {
		return -1
	}

	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -2
	}

	wrapper.dnsConf.Ipv6.GetType = C.GoString(getType)

	return 0
}

//export DdnsUpdateOnce
func DdnsUpdateOnce(instanceID C.int) C.int {
	ddnsInstancesMutex.RLock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.RUnlock()

	if !ok {
		return -1
	}

	wrapper.dnsProvider.Init(wrapper.dnsConf, wrapper.ipv4cache, wrapper.ipv6cache)

	domains := wrapper.dnsProvider.AddUpdateDomainRecords()

	var result string
	for _, domain := range domains.Ipv4Domains {
		result += fmt.Sprintf("IPv4 %s: %s\n", domain.String(), domain.UpdateStatus)
	}
	for _, domain := range domains.Ipv6Domains {
		result += fmt.Sprintf("IPv6 %s: %s\n", domain.String(), domain.UpdateStatus)
	}

	wrapper.lastResult = result
	log.Printf("[DDNS %d] Update completed:\n%s", instanceID, result)

	return 0
}

//export DdnsStartAutoUpdate
func DdnsStartAutoUpdate(
	instanceID C.int,
	intervalSeconds C.int,
) C.int {
	ddnsInstancesMutex.Lock()
	wrapper, ok := ddnsInstances[int(instanceID)]
	ddnsInstancesMutex.Unlock()

	if !ok {
		return -1
	}

	if wrapper.isRunning {
		return -3
	}

	wrapper.isRunning = true

	wrapper.dnsProvider.Init(wrapper.dnsConf, wrapper.ipv4cache, wrapper.ipv6cache)

	go func() {
		ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
		defer ticker.Stop()

		domains := wrapper.dnsProvider.AddUpdateDomainRecords()
		for _, domain := range domains.Ipv4Domains {
			log.Printf("[DDNS %d] IPv4 %s: %s", instanceID, domain.String(), domain.UpdateStatus)
		}
		for _, domain := range domains.Ipv6Domains {
			log.Printf("[DDNS %d] IPv6 %s: %s", instanceID, domain.String(), domain.UpdateStatus)
		}

		for {
			select {
			case <-ticker.C:
				domains := wrapper.dnsProvider.AddUpdateDomainRecords()
				for _, domain := range domains.Ipv4Domains {
					log.Printf("[DDNS %d] IPv4 %s: %s", instanceID, domain.String(), domain.UpdateStatus)
				}
				for _, domain := range domains.Ipv6Domains {
					log.Printf("[DDNS %d] IPv6 %s: %s", instanceID, domain.String(), domain.UpdateStatus)
				}
			case <-wrapper.stopCh:
				log.Printf("[DDNS %d] Auto-update stopped", instanceID)
				return
			}
		}
	}()

	return 0
}

//export DdnsStopAutoUpdate
func DdnsStopAutoUpdate(instanceID C.int) C.int {
	ddnsInstancesMutex.Lock()
	defer ddnsInstancesMutex.Unlock()

	wrapper, ok := ddnsInstances[int(instanceID)]
	if !ok {
		return -1
	}

	if !wrapper.isRunning {
		return 0 // 没有在运行
	}

	close(wrapper.stopCh)
	wrapper.stopCh = make(chan struct{})
	wrapper.isRunning = false

	return 0
}

//export DdnsDestroyInstance
func DdnsDestroyInstance(instanceID C.int) C.int {
	ddnsInstancesMutex.Lock()
	defer ddnsInstancesMutex.Unlock()

	wrapper, ok := ddnsInstances[int(instanceID)]
	if !ok {
		return -1
	}

	// 确保自动更新已停止
	if wrapper.isRunning {
		close(wrapper.stopCh)
		wrapper.isRunning = false
	}

	// 从全局 map 中删除
	delete(ddnsInstances, int(instanceID))

	return 0
}

//export DdnsFreeString
func DdnsFreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

//export DdnsCleanup
func DdnsCleanup() {
	ddnsInstancesMutex.Lock()
	defer ddnsInstancesMutex.Unlock()

	// 停止所有实例
	for _, wrapper := range ddnsInstances {
		if wrapper.isRunning {
			close(wrapper.stopCh)
		}
	}

	// 清空 map
	ddnsInstances = make(map[int]*ddnsWrapper)
}
