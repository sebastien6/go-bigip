package bigip

import (
	//"encoding/json"
	//"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestHashName(t *testing.T) {
	resp := HashName("/Common/sat")
	assert.Equal(t, resp, "9afAWDUoawpiNnfSfSGtMQ")
}

func TestHashIP(t *testing.T) {
	resp := HashIP("192.168.0.30", "255.255.255.255")
	t.Log(resp)
	assert.Equal(t, resp, "2S_b6WCJRsVKz9xgrtxYPA")
}

type ASMTestSuite struct {
	suite.Suite
	Client          *BigIP
	Server          *httptest.Server
	LastRequest     *http.Request
	LastRequestBody string
	ResponseFunc    func(http.ResponseWriter, *http.Request)
}

func (s *ASMTestSuite) SetupSuite() {
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		s.LastRequestBody = string(body)
		s.LastRequest = r
		if s.ResponseFunc != nil {
			s.ResponseFunc(w, r)
		}
	}))

	s.Client = NewSession(s.Server.URL, "", "", nil)
}

func (s *ASMTestSuite) TearDownSuite() {
	s.Server.Close()
}

func (s *ASMTestSuite) SetupTest() {
	s.ResponseFunc = nil
	s.LastRequest = nil
}

func TestAsmSuite(t *testing.T) {
	suite.Run(t, new(ASMTestSuite))
}

func (s *ASMTestSuite) TestGetWhitelistIP() {
	s.ResponseFunc = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"ignoreIpReputation": true,
			"blockRequests": "policy-default",
			"ignoreAnomalies": false,
			"neverLogRequests": false,
			"ipAddress": "192.168.0.10",
			"lastUpdateMicros": 1564274172000000,
			"description": "seb go test",
			"kind": "tm:asm:policies:whitelist-ips:whitelist-ipstate",
			"ipMask": "255.255.255.255",
			"id": "uXke_A7Hl-krxXlwfBvs2g",
			"trustedByPolicyBuilder": false
			}`))
	}

	_, err := s.Client.GetWhitelistIP("E3fv4tmMxHNN-E4m7XmqBw", "uXke_A7Hl-krxXlwfBvs2g")
	assert.Nil(s.T(), err)

}
