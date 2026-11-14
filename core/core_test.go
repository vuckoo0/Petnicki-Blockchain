package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBlockJSONEncodesNilTransactionsAsEmptyArray(t *testing.T) {
	data, err := json.Marshal(Block{})
	if err != nil {
		t.Fatalf("marshal block: %v", err)
	}
	if got, want := string(data), `{"height":0,"prev_hash":"","miner":"","nonce":0,"transactions":[]}`; got != want {
		t.Fatalf("encoded block = %s, want %s", got, want)
	}
}

func TestGetBlockEncodesLegacyNilTransactionsAsEmptyArray(t *testing.T) {
	n := newNode("", 0, nil, false, "")
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	n.blocks[hash] = &storedBlock{Block: Block{Height: 1}, Hash: hash}

	request := httptest.NewRequest(http.MethodGet, "/blocks/"+hash, nil)
	request.SetPathValue("hash", hash)
	response := httptest.NewRecorder()
	n.handleGetBlock(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &encoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := string(encoded["transactions"]), "[]"; got != want {
		t.Fatalf("transactions = %s, want %s", got, want)
	}
}

func TestCanvasRendersModernLayout(t *testing.T) {
	n := newNode("", 0, nil, false, "")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	n.handleCanvas(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	if !strings.Contains(body, "Petnica Canvas") || !strings.Contains(body, "Nova transakcija") {
		t.Fatal("canvas does not include the expected dashboard content")
	}
	if strings.Contains(body, "%!") {
		t.Fatalf("canvas contains an invalid fmt directive: %s", body)
	}
}
