package u2f

import (
	"log"
	"testing"
)

func TestVirtualKey(t *testing.T) {

	vk, err := NewVirtualKey()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	var app_id string = "http://localhost"
	var trustedFacets = []string{app_id}
	var registrations []Registration
	var counter uint32

	// Generate registration request
	c1, _ := NewChallenge(app_id, trustedFacets)
	req := NewWebRegisterRequest(c1, registrations)

	// Pass to virtual token
	resp, err := vk.HandleRegisterRequest(*req)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Register virtual token
	reg, err := Register(*resp, *c1, &Config{SkipAttestationVerify: true})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	registrations = append(registrations, *reg)

	// Generate authentication request
	c2, _ := NewChallenge(app_id, trustedFacets)
	signReq := c2.SignRequest(registrations)

	// Pass to virtual token
	signResp, err := vk.HandleAuthenticationRequest(*signReq)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Read response from the token
	for _, reg := range registrations {
		newCounter, authErr := reg.Authenticate(*signResp, *c2, counter)
		if authErr == nil {
			log.Printf("newCounter: %d", newCounter)
			return
		} else {
			t.Error(err)
			t.FailNow()
		}
	}

}
