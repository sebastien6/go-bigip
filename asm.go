package bigip

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	uriAsm         = "asm"
	uriTasks       = "tasks"
	uriApplyPolicy = "apply-policy"
	uriPolicies    = "policies"
	uriWhitelistIP = "whitelist-ips"
	uriAttackTypes = "attack-types"
)

// HashName Calculate the corresponding hash used in bigip URI for an object name (policy name, signature name, etc...)
// useful to modify or delete an ASM object based on its name to retreive its corresponding URI
// bigip ASM is using MD5 hash of the ASM object name to build a URI and link the item to the URI
// the hash is calculated based on the following formula:
// 1. Create the MD5 digest from the name (yields 128 bits of binary data)
// 2. Encode it using base64 (yields 24 characters)
// 3. Trim the last two "==".
// Transliterate "+" and "/" to "-" and "_" respectively.
func HashName(name string) (hash string) {
	h := md5.New()
	io.WriteString(h, name)
	hash = strings.TrimSuffix(base64.StdEncoding.EncodeToString(h.Sum(nil)), "==")
	r := strings.NewReplacer("+", "-", "/", "_")
	return r.Replace(hash)
}

// HashIP Calculate the corresponding hash used in bigip URI for an IP
// useful to modify or delete a whitelist IP based on its IP/netmask to retreive its corresponding URI
// bigip ASM is using MD5 hash of the ASM object name to build a uri and link the item to the URI
// whitelist IP hash are calculated with the following formula:
// 1. Create a source input string by concatenating the elements using the ###UNLIKELY_DELIMITER### delimiter.
// 2. Create the MD5 digest from the source input (yields 128 bits of binary data)
// 3. Encode it using base64 (yields 24 characters)
// 4. Trim the last two "==" (22 characters)
// Transliterate "+" and "/" to "-" and "_" respectively.
func HashIP(ipaddress, ipmask string) (hash string) {
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%s###UNLIKELY_DELIMITER###%s", ipaddress, ipmask))
	hash = strings.TrimSuffix(base64.StdEncoding.EncodeToString(h.Sum(nil)), "==")
	r := strings.NewReplacer("+", "-", "/", "_")
	return r.Replace(hash)
}

// ApplyPolicy request content
type ApplyPolicyLink struct {
	PolicyReference struct {
		Link string `json:"link"`
	} `json:"policyReference"`
}

// ApplyPolicy Post a task to manually apply a policy that protects a website
func (b *BigIP) ApplyPolicy(policyHash string) error {
	var apply ApplyPolicyLink
	apply.PolicyReference.Link = "https://localhost/mgmt/tm/asm/policies/" + policyHash
	return b.post(&apply, uriAsm, uriTasks, uriApplyPolicy)
}

// WhitelistIPs contains a list of every whitelist IPs associated to an ASM policy on the BIG-IP system.
type WhitelistIPs struct {
	WhitelistIps []WhitelistIP `json:"items"`
}

//WhitelistIP contains information about each whitelist IPs associated to an ASM policy. You can use all
// of these fields when modifying a whitelist IPs associated to an ASM policy.
type WhitelistIP struct {
	IgnoreIPReputation     bool   `json:"ignoreIpReputation"`
	BlockRequests          string `json:"blockRequests"`
	IgnoreAnomalies        bool   `json:"ignoreAnomalies"`
	NeverLogRequests       bool   `json:"neverLogRequests"`
	IPAddress              string `json:"ipAddress"`
	Description            string `json:"description"`
	NeverLearnRequests     bool   `json:"neverLearnRequests"`
	IPMask                 string `json:"ipMask"`
	ID                     string `json:"id"`
	TrustedByPolicyBuilder bool   `json:"trustedByPolicyBuilder"`
}

// WhitelistIPs Get Whitelist-IPs associated to an ASM policy
func (b *BigIP) WhitelistIPs(policyHash string) (*WhitelistIPs, error) {
	var wlips WhitelistIPs
	err, _ := b.getForEntity(&wlips, uriAsm, uriPolicies, policyHash, uriWhitelistIP)
	if err != nil {
		return nil, err
	}

	return &wlips, nil
}

// GetWhitelistIP Get a Whitelist-Ip associated with an ASM policy
func (b BigIP) GetWhitelistIP(policyHash string, whitelistIPName string) (*WhitelistIP, error) {
	var wlip WhitelistIP
	err, ok := b.getForEntity(&wlip, uriAsm, uriPolicies, policyHash, uriWhitelistIP, whitelistIPName)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &wlip, nil
}

// CreateWhitelistIP create a new Whitelist-Ip associated to an ASM policy
func (b *BigIP) CreateWhitelistIP(policyHash string, wlip *WhitelistIP) error {
	err := b.post(wlip, uriAsm, uriPolicies, policyHash, uriWhitelistIP)
	if err != nil {
		return err
	}

	return b.ApplyPolicy(policyHash)
}

// CreateWhitelistIP update an existing Whitelist-Ip associated to an ASM policy
func (b *BigIP) UpdateWhitelistIP(policyHash string, wlip *WhitelistIP) error {
	uriWhitelistIPHash := HashIP(wlip.IPAddress, wlip.IPMask)
	err := b.post(wlip, uriAsm, uriPolicies, policyHash, uriWhitelistIP, uriWhitelistIPHash)
	if err != nil {
		return err
	}

	return b.ApplyPolicy(policyHash)
}

