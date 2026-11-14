package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	hex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)
	hex6   = regexp.MustCompile(`^[0-9a-f]{6}$`)
	number = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

const (
	defaultDifficulty        = 20
	maxJSONInteger           = uint64(9007199254740991)
	genesisHash              = "0000000000000000000000000000000000000000000000000000000000000000"
	simulatedLossProbability = 0.05
	simulatedLagMin          = 100 * time.Millisecond
	simulatedLagMax          = 500 * time.Millisecond
)

type Transaction struct {
	Type      string `json:"type"`
	Sender    string `json:"sender"`
	Nonce     uint64 `json:"nonce"`
	Parcel    uint8  `json:"parcel"`
	Value     string `json:"value"`
	Signature string `json:"signature"`
}

type Block struct {
	Height       uint64        `json:"height"`
	PrevHash     string        `json:"prev_hash"`
	Miner        string        `json:"miner"`
	Nonce        uint64        `json:"nonce"`
	Transactions []Transaction `json:"transactions"`
}

// MarshalJSON keeps empty transaction lists consistent across the wire and
// persisted node state. Older blocks loaded from JSON may have a nil slice
// (for example after decoding a legacy "transactions": null value), but the
// protocol represents an empty block as an empty array.
func (b Block) MarshalJSON() ([]byte, error) {
	if b.Transactions == nil {
		b.Transactions = []Transaction{}
	}
	type blockJSON Block
	return json.Marshal(blockJSON(b))
}

type Parcel struct {
	Owner string `json:"owner,omitempty"`
	Color string `json:"color,omitempty"`
}

type ChainState struct {
	Parcels   [256]Parcel
	Nonces    map[string]uint64
	Exhausted map[string]bool
}
type storedBlock struct {
	Block Block
	Hash  string
	State ChainState
}
type diskData struct {
	Blocks     []Block       `json:"blocks"`
	Mempool    []Transaction `json:"mempool"`
	PrivateKey string        `json:"private_key,omitempty"`
}

type Node struct {
	mu         sync.RWMutex
	blocks     map[string]*storedBlock
	orphans    map[string]Block
	tip        string
	mempool    []Transaction
	miner      string
	difficulty int
	peers      []string
	client     *http.Client
	lag        bool
	dataPath   string
	privateKey ed25519.PrivateKey
}

func newNode(miner string, difficulty int, peers []string, lag bool, dataPath string) *Node {
	n := &Node{blocks: map[string]*storedBlock{}, orphans: map[string]Block{}, tip: genesisHash, miner: miner, difficulty: difficulty, peers: peers, lag: lag, dataPath: dataPath, client: &http.Client{Timeout: 5 * time.Second}}
	n.blocks[genesisHash] = &storedBlock{Block: Block{Height: 0, PrevHash: genesisHash, Miner: genesisHash, Transactions: []Transaction{}}, Hash: genesisHash, State: emptyState()}
	return n
}

func emptyState() ChainState {
	return ChainState{Nonces: map[string]uint64{}, Exhausted: map[string]bool{}}
}
func cloneState(s ChainState) ChainState {
	c := ChainState{Parcels: s.Parcels, Nonces: make(map[string]uint64, len(s.Nonces)), Exhausted: make(map[string]bool, len(s.Exhausted))}
	for k, v := range s.Nonces {
		c.Nonces[k] = v
	}
	for k, v := range s.Exhausted {
		c.Exhausted[k] = v
	}
	return c
}

func parsePeers(value string) []string {
	var peers []string
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimRight(strings.TrimSpace(raw), "/")
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			peers = append(peers, raw)
		}
	}
	return peers
}

func hashBlock(b Block) string {
	sum := sha256.Sum256(blockBytes(b))
	return hex.EncodeToString(sum[:])
}

// txPayload and blockBytes are the exact byte formats defined by the protocol.
func txPayload(t Transaction) string {
	return t.Type + "|" + t.Sender + "|" + strconv.FormatUint(t.Nonce, 10) + "|" + strconv.FormatUint(uint64(t.Parcel), 10) + "|" + t.Value
}
func blockBytes(b Block) []byte {
	var out strings.Builder
	out.WriteString(strconv.FormatUint(b.Height, 10))
	out.WriteByte('|')
	out.WriteString(b.PrevHash)
	out.WriteByte('|')
	out.WriteString(b.Miner)
	out.WriteByte('|')
	out.WriteString(strconv.FormatUint(b.Nonce, 10))
	for _, t := range b.Transactions {
		out.WriteByte('\n')
		out.WriteString(txPayload(t))
		out.WriteByte('|')
		out.WriteString(t.Signature)
	}
	return []byte(out.String())
}
func hasLeadingZeroBits(hashHex string, bits int) bool {
	b, err := hex.DecodeString(hashHex)
	if err != nil || bits < 0 || bits > len(b)*8 {
		return false
	}
	for i := 0; i < bits/8; i++ {
		if b[i] != 0 {
			return false
		}
	}
	left := bits % 8
	return left == 0 || b[bits/8]&(byte(0xff)<<(8-left)) == 0
}
func validateTransactionSyntax(t Transaction) error {
	if t.Type != "paint" && t.Type != "transfer" {
		return errors.New("type must be paint or transfer")
	}
	if !hex64.MatchString(t.Sender) {
		return errors.New("sender must be 64 lowercase hex characters")
	}
	if t.Nonce > maxJSONInteger {
		return errors.New("nonce exceeds 2^53-1")
	}
	if (t.Type == "paint" && !hex6.MatchString(t.Value)) || (t.Type == "transfer" && !hex64.MatchString(t.Value)) {
		return errors.New("invalid value for transaction type")
	}
	if !hex128.MatchString(t.Signature) {
		return errors.New("signature must be 128 lowercase hex characters")
	}
	public, _ := hex.DecodeString(t.Sender)
	sig, _ := hex.DecodeString(t.Signature)
	if !ed25519.Verify(ed25519.PublicKey(public), []byte(txPayload(t)), sig) {
		return errors.New("invalid Ed25519 signature")
	}
	return nil
}
func applyTransaction(s *ChainState, t Transaction) error {
	if err := validateTransactionSyntax(t); err != nil {
		return err
	}
	if s.Exhausted[t.Sender] || s.Nonces[t.Sender] != t.Nonce {
		return errors.New("unexpected sender nonce")
	}
	p := &s.Parcels[t.Parcel]
	if p.Owner != t.Sender {
		return errors.New("sender does not own parcel")
	}
	if t.Type == "paint" {
		p.Color = t.Value
	} else {
		p.Owner = t.Value
	}
	if t.Nonce == maxJSONInteger {
		s.Exhausted[t.Sender] = true
	} else {
		s.Nonces[t.Sender]++
	}
	return nil
}
func validateBlockSyntax(b Block) error {
	if b.Height == 0 || b.Height > maxJSONInteger {
		return errors.New("invalid height")
	}
	if b.Nonce > maxJSONInteger {
		return errors.New("invalid mining nonce")
	}
	if !hex64.MatchString(b.PrevHash) || !hex64.MatchString(b.Miner) {
		return errors.New("invalid parent hash or miner key")
	}
	for _, tx := range b.Transactions {
		if err := validateTransactionSyntax(tx); err != nil {
			return err
		}
	}
	return nil
}
func (n *Node) validateKnownBlock(b Block) (*storedBlock, error) {
	if err := validateBlockSyntax(b); err != nil {
		return nil, err
	}
	hash := hashBlock(b)
	if !hasLeadingZeroBits(hash, n.difficulty) {
		return nil, errors.New("insufficient proof of work")
	}
	parent := n.blocks[b.PrevHash]
	if parent == nil {
		return nil, errMissingParent
	}
	if b.Height != parent.Block.Height+1 {
		return nil, errors.New("height does not extend parent")
	}
	state := cloneState(parent.State)
	for _, tx := range b.Transactions {
		if err := applyTransaction(&state, tx); err != nil {
			return nil, fmt.Errorf("transaction: %w", err)
		}
	}
	parcel, _ := hex.DecodeString(hash[len(hash)-2:])
	if state.Parcels[parcel[0]].Owner == "" {
		state.Parcels[parcel[0]].Owner = b.Miner
	}
	return &storedBlock{Block: b, Hash: hash, State: state}, nil
}

var errMissingParent = errors.New("missing parent")

func (n *Node) acceptBlockLocked(b Block) (known bool, missing bool, err error) {
	hash := hashBlock(b)
	if _, ok := n.blocks[hash]; ok {
		return true, false, nil
	}
	stored, err := n.validateKnownBlock(b)
	if errors.Is(err, errMissingParent) {
		n.orphans[hash] = b
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	n.blocks[hash] = stored
	n.maybeChooseTipLocked(stored)
	n.resolveOrphansLocked(hash)
	n.revalidateMempoolLocked()
	_ = n.saveLocked()
	return false, false, nil
}

func (n *Node) resolveOrphansLocked(parentHash string) {
	for {
		progress := false
		for hash, b := range n.orphans {
			if b.PrevHash != parentHash {
				continue
			}
			delete(n.orphans, hash)
			stored, err := n.validateKnownBlock(b)
			if err == nil {
				n.blocks[stored.Hash] = stored
				n.maybeChooseTipLocked(stored)
				parentHash = stored.Hash
				progress = true
			}
		}
		if !progress {
			return
		}
	}
}

func (n *Node) maybeChooseTipLocked(candidate *storedBlock) {
	current := n.blocks[n.tip]
	if candidate.Block.Height > current.Block.Height || (candidate.Block.Height == current.Block.Height && candidate.Hash > current.Hash) {
		n.tip = candidate.Hash
	}
}

func (n *Node) revalidateMempoolLocked() {
	state := cloneState(n.blocks[n.tip].State)
	valid := make([]Transaction, 0, len(n.mempool))
	for _, tx := range n.mempool {
		if applyTransaction(&state, tx) == nil {
			valid = append(valid, tx)
		}
	}
	n.mempool = valid
}

func (n *Node) mineForever() {
	for {
		n.mu.RLock()
		parent := n.blocks[n.tip]
		block := Block{Height: parent.Block.Height + 1, PrevHash: parent.Hash, Miner: n.miner, Transactions: slices.Clone(n.mempool)}
		n.mu.RUnlock()
		for nonce := uint64(0); nonce <= maxJSONInteger; nonce++ {
			block.Nonce = nonce
			hash := hashBlock(block)
			if !hasLeadingZeroBits(hash, n.difficulty) {
				continue
			}
			n.mu.Lock()
			// Do not publish work that was made stale by a new selected tip.
			if n.tip == block.PrevHash {
				_, _, err := n.acceptBlockLocked(block)
				if err == nil {
					fmt.Printf("Mined block: height=%d hash=%s\n", block.Height, hash)
				}
			}
			n.mu.Unlock()
			if n.hasBlock(hash) {
				n.broadcastBlock(block)
			}
			break
		}
	}
}

func (n *Node) hasBlock(hash string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	_, ok := n.blocks[hash]
	return ok
}

func (n *Node) handleTip(w http.ResponseWriter, r *http.Request) {
	n.mu.RLock()
	b := n.blocks[n.tip]
	n.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"height": b.Block.Height, "hash": b.Hash})
}

func (n *Node) handleCanvas(w http.ResponseWriter, r *http.Request) {
	n.mu.RLock()
	tip, miner, state := n.blocks[n.tip], n.miner, cloneState(n.blocks[n.tip].State)
	n.mu.RUnlock()
	var cells strings.Builder
	for i, p := range state.Parcels {
		style := "background:#eef2f7"
		class := "cell"
		if p.Color != "" {
			style = "background:#" + p.Color
		}
		if p.Owner != "" {
			class += " owned"
			if p.Owner == miner {
				class += " mine"
			}
		}
		label := fmt.Sprintf("parcel %d (%d, %d)", i, i%16, i/16)
		if p.Owner != "" {
			label += " owner: " + p.Owner
		}
		cells.WriteString(fmt.Sprintf(`<button class="%s" type="button" data-parcel="%d" style="%s" title="%s" aria-label="%s"></button>`, class, i, style, html.EscapeString(label), html.EscapeString(label)))
	}
	message := html.EscapeString(r.URL.Query().Get("message"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html lang="sr"><head><title>Petnica Canvas</title><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="10"><style>:root{color-scheme:light;--ink:#172033;--muted:#69758b;--line:#e5eaf2;--surface:#fff;--canvas:#f5f7fb;--blue:#2563eb;--blue-deep:#1d4ed8;--shadow:0 18px 50px rgba(31,45,73,.10)}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#f8faff 0,#f3f6fb 54rem,#edf3ff 100%%);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.page{max-width:1180px;margin:0 auto;padding:32px 24px 48px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:12px}.brand-mark{display:grid;place-items:center;width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);box-shadow:0 8px 18px #2563eb38;color:#fff;font-size:14px;font-weight:800;letter-spacing:.06em}.brand h1{margin:0;font-size:20px;letter-spacing:-.035em}.brand p{margin:3px 0 0;color:var(--muted);font-size:13px}.status{display:flex;align-items:center;gap:8px;border:1px solid #dbe7fe;border-radius:999px;background:#f8fbff;padding:8px 11px;color:#315a9b;font-size:12px;font-weight:650}.status::before{content:"";width:7px;height:7px;border-radius:50%%;background:#22c55e;box-shadow:0 0 0 4px #dcfce7}.dashboard{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:22px;align-items:start}.panel{border:1px solid var(--line);border-radius:20px;background:var(--surface);box-shadow:var(--shadow)}.board{padding:24px}.panel-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:20px}.eyebrow{margin:0 0 5px;color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.09em;text-transform:uppercase}.panel h2{margin:0;font-size:19px;letter-spacing:-.03em}.panel-heading p:last-child{margin:6px 0 0;color:var(--muted);font-size:13px}.height{flex:none;border-radius:10px;background:#eff6ff;padding:8px 10px;color:#1e4d9b;font-size:12px;font-weight:750}.grid-frame{overflow:auto;border:1px solid #e7edf6;border-radius:16px;background:linear-gradient(135deg,#f8fbff,#f2f6fc);padding:15px}.grid{display:grid;grid-template-columns:repeat(16,32px);gap:4px;width:max-content}.cell{width:32px;height:32px;padding:0;border:1px solid #dce4ee;border-radius:8px;cursor:pointer;transition:transform .15s ease,box-shadow .15s ease,outline .15s ease}.cell:hover{position:relative;z-index:1;transform:scale(1.13);outline:2px solid #60a5fa;outline-offset:2px;box-shadow:0 5px 12px #1e3a5f30}.cell.owned{border-color:#64748b;box-shadow:inset 0 0 0 1px #ffffff80}.cell.mine{border:2px solid #1d4ed8;box-shadow:inset 0 0 0 1px #fff,0 0 0 2px #bfdbfe}.cell.selected{position:relative;z-index:2;outline:3px solid var(--blue);outline-offset:2px;box-shadow:0 6px 16px #2563eb3b}.legend{display:flex;flex-wrap:wrap;gap:14px;margin:17px 2px 0;color:var(--muted);font-size:12px}.legend span{display:flex;align-items:center;gap:7px}.legend i{display:block;width:12px;height:12px;border:1px solid #dce4ee;border-radius:4px;background:#eef2f7}.legend .owned-dot{border-color:#64748b;background:#fff}.legend .mine-dot{border:2px solid #1d4ed8;background:#dbeafe}.controls{padding:24px}.controls h2{margin:0;font-size:18px;letter-spacing:-.03em}.controls .intro{margin:7px 0 20px;color:var(--muted);font-size:13px;line-height:1.55}.controls label{display:block;margin:14px 0 6px;color:#40506a;font-size:12px;font-weight:720}.controls input{width:100%%;border:1px solid #dce3ed;border-radius:10px;background:#fbfcfe;padding:10px 11px;color:var(--ink);font:inherit;font-size:13px;outline:none;transition:border-color .15s,box-shadow .15s}.controls input:focus{border-color:#60a5fa;box-shadow:0 0 0 3px #dbeafe}.controls input[type=color]{height:43px;padding:5px;cursor:pointer}.actions{display:grid;gap:9px;margin-top:19px}.controls button{border:0;border-radius:10px;padding:11px 13px;background:var(--blue);box-shadow:0 5px 12px #2563eb2e;color:#fff;cursor:pointer;font:inherit;font-size:13px;font-weight:750;transition:background .15s,transform .15s,box-shadow .15s}.controls button:hover{background:var(--blue-deep);box-shadow:0 8px 18px #2563eb38;transform:translateY(-1px)}.controls button.secondary{background:#eff6ff;box-shadow:none;color:#2454a0}.controls button.secondary:hover{background:#dbeafe}.message{min-height:19px;margin:16px 0 0;border-radius:8px;color:#18794e;font-size:12px;font-weight:650;line-height:1.45}.chain-info{margin-top:22px;border-top:1px solid var(--line);padding-top:17px}.chain-info span{display:block;margin-bottom:4px;color:var(--muted);font-size:11px;font-weight:750;letter-spacing:.06em;text-transform:uppercase}.chain-info code{display:block;overflow:hidden;color:#52627a;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;text-overflow:ellipsis;white-space:nowrap}@media(max-width:820px){.dashboard{grid-template-columns:1fr}.controls{order:-1}.page{padding:20px 16px 32px}}@media(max-width:500px){.topbar{align-items:flex-start;flex-direction:column}.board,.controls{padding:18px}.panel-heading{align-items:flex-start;flex-direction:column}.grid-frame{padding:11px}}</style></head><body><main class="page"><header class="topbar"><div class="brand"><div class="brand-mark">PB</div><div><h1>Petnica Canvas</h1><p>Vizuelni registar vlasništva na blokčejnu</p></div></div><div class="status">Mreža aktivna</div></header><div class="dashboard"><section class="panel board"><div class="panel-heading"><div><p class="eyebrow">Mapa parcela</p><h2>Stanje mreže</h2><p>Izaberi parcelu da bi pripremio transakciju.</p></div><div class="height">Blok %d</div></div><div class="grid-frame"><div class="grid">%s</div></div><div class="legend"><span><i></i> Slobodna parcela</span><span><i class="owned-dot"></i> U vlasništvu</span><span><i class="mine-dot"></i> Tvoja parcela</span></div></section><form class="panel controls" method="post" action="/canvas/transactions"><p class="eyebrow">Nova transakcija</p><h2>Izmeni parcelu</h2><p class="intro">Odaberi polje sa mape, zatim promeni boju ili prenesi vlasništvo.</p><label for="parcel">Izabrana parcela</label><input id="parcel" name="parcel" type="number" min="0" max="255" required readonly placeholder="Izaberi polje na mapi"><label for="color">Boja parcele</label><input id="color" name="color" type="color" value="#337ab7"><div class="actions"><button name="action" value="paint" type="submit">Sačuvaj boju</button></div><label for="recipient">Javni ključ primaoca</label><input id="recipient" name="recipient" type="text" pattern="[0-9a-f]{64}" minlength="64" maxlength="64" placeholder="64 heksadecimalna znaka"><div class="actions"><button class="secondary" name="action" value="transfer" type="submit">Prenesi vlasništvo</button></div><p class="message">%s</p><div class="chain-info"><span>Hash vrha lanca</span><code title="%s">%s</code><span style="margin-top:13px">Tvoj javni ključ</span><code title="%s">%s</code></div></form></div></main><script>const parcel=document.getElementById('parcel');let selected;document.querySelectorAll('.cell').forEach(cell=>cell.addEventListener('click',()=>{if(selected)selected.classList.remove('selected');selected=cell;selected.classList.add('selected');parcel.value=cell.dataset.parcel;}));</script></body></html>`, tip.Block.Height, cells.String(), message, tip.Hash, tip.Hash, miner, miner)
}

func (n *Node) handleCanvasTransaction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?message="+url.QueryEscape("Invalid form submission."), http.StatusSeeOther)
		return
	}
	parcel, err := strconv.ParseUint(r.FormValue("parcel"), 10, 8)
	if err != nil {
		http.Redirect(w, r, "/?message="+url.QueryEscape("Select a parcel first."), http.StatusSeeOther)
		return
	}
	action, value := r.FormValue("action"), ""
	switch action {
	case "paint":
		value = strings.TrimPrefix(strings.ToLower(r.FormValue("color")), "#")
	case "transfer":
		value = strings.TrimSpace(r.FormValue("recipient"))
	default:
		http.Redirect(w, r, "/?message="+url.QueryEscape("Unknown action."), http.StatusSeeOther)
		return
	}
	if _, err := n.createLocalTransaction(action, uint8(parcel), value); err != nil {
		http.Redirect(w, r, "/?message="+url.QueryEscape("Transaction rejected: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?message="+url.QueryEscape("Transaction queued for mining."), http.StatusSeeOther)
}

func (n *Node) createLocalTransaction(kind string, parcel uint8, value string) (Transaction, error) {
	n.mu.Lock()
	if len(n.privateKey) != ed25519.PrivateKeySize {
		n.mu.Unlock()
		return Transaction{}, errors.New("node private key is unavailable")
	}
	state := cloneState(n.blocks[n.tip].State)
	for _, queued := range n.mempool {
		_ = applyTransaction(&state, queued)
	}
	tx := Transaction{Type: kind, Sender: n.miner, Nonce: state.Nonces[n.miner], Parcel: parcel, Value: value}
	tx.Signature = hex.EncodeToString(ed25519.Sign(n.privateKey, []byte(txPayload(tx))))
	if err := applyTransaction(&state, tx); err != nil {
		n.mu.Unlock()
		return Transaction{}, err
	}
	n.mempool = append(n.mempool, tx)
	_ = n.saveLocked()
	n.mu.Unlock()
	go n.broadcastTransaction(tx)
	return tx, nil
}

func (n *Node) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	n.mu.RLock()
	b := n.blocks[hash]
	n.mu.RUnlock()
	if b == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	block := b.Block
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if block.Transactions == nil {
		block.Transactions = []Transaction{}
	}
	_ = json.NewEncoder(w).Encode(block)
}

func (n *Node) handleTransaction(w http.ResponseWriter, r *http.Request) {
	tx, err := decodeTransaction(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	for _, old := range n.mempool {
		if old == tx {
			n.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	state := cloneState(n.blocks[n.tip].State)
	for _, queued := range n.mempool {
		_ = applyTransaction(&state, queued)
	}
	if err := applyTransaction(&state, tx); err != nil {
		n.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n.mempool = append(n.mempool, tx)
	_ = n.saveLocked()
	n.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
	go n.broadcastTransaction(tx)
}

func (n *Node) handleBlock(w http.ResponseWriter, r *http.Request) {
	b, err := decodeBlock(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Syntax, signatures, and PoW can be checked even if its parent is absent.
	if err := validateBlockSyntax(b); err != nil || !hasLeadingZeroBits(hashBlock(b), n.difficulty) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	known, missing, err := n.acceptBlockLocked(b)
	n.mu.Unlock()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if missing {
		w.WriteHeader(http.StatusAccepted)
		go n.fetchChain(b.PrevHash)
		return
	}
	w.WriteHeader(http.StatusOK)
	if !known {
		go n.broadcastBlock(b)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// Strict decoders reject duplicate, missing, and unknown fields. Encoding/json
// alone accepts duplicate object keys, which the protocol explicitly forbids.
func decodeTransaction(r io.Reader) (Transaction, error) {
	values, err := decodeObject(r)
	if err != nil {
		return Transaction{}, err
	}
	required := []string{"type", "sender", "nonce", "parcel", "value", "signature"}
	if err := exactFields(values, required); err != nil {
		return Transaction{}, err
	}
	typeValue, err := stringValue(values["type"])
	if err != nil {
		return Transaction{}, err
	}
	sender, err := stringValue(values["sender"])
	if err != nil {
		return Transaction{}, err
	}
	nonce, err := uintValue(values["nonce"], maxJSONInteger)
	if err != nil {
		return Transaction{}, err
	}
	parcel, err := uintValue(values["parcel"], 255)
	if err != nil {
		return Transaction{}, err
	}
	value, err := stringValue(values["value"])
	if err != nil {
		return Transaction{}, err
	}
	signature, err := stringValue(values["signature"])
	if err != nil {
		return Transaction{}, err
	}
	t := Transaction{Type: typeValue, Sender: sender, Nonce: nonce, Parcel: uint8(parcel), Value: value, Signature: signature}
	return t, validateTransactionSyntax(t)
}

func decodeBlock(r io.Reader) (Block, error) {
	values, err := decodeObject(r)
	if err != nil {
		return Block{}, err
	}
	required := []string{"height", "prev_hash", "miner", "nonce", "transactions"}
	if err := exactFields(values, required); err != nil {
		return Block{}, err
	}
	height, err := uintValue(values["height"], maxJSONInteger)
	if err != nil {
		return Block{}, err
	}
	prev, err := stringValue(values["prev_hash"])
	if err != nil {
		return Block{}, err
	}
	miner, err := stringValue(values["miner"])
	if err != nil {
		return Block{}, err
	}
	nonce, err := uintValue(values["nonce"], maxJSONInteger)
	if err != nil {
		return Block{}, err
	}
	if trimmed := bytes.TrimSpace(values["transactions"]); len(trimmed) < 2 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']' {
		return Block{}, errors.New("transactions must be an array")
	}
	var rawTxs []json.RawMessage
	if err := json.Unmarshal(values["transactions"], &rawTxs); err != nil {
		return Block{}, errors.New("transactions must be an array")
	}
	txs := make([]Transaction, 0, len(rawTxs))
	for _, raw := range rawTxs {
		tx, err := decodeTransaction(bytes.NewReader(raw))
		if err != nil {
			return Block{}, err
		}
		txs = append(txs, tx)
	}
	b := Block{Height: height, PrevHash: prev, Miner: miner, Nonce: nonce, Transactions: txs}
	return b, validateBlockSyntax(b)
}

func decodeObject(r io.Reader) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(io.LimitReader(r, 4<<20))
	d.UseNumber()
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("JSON object required")
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("invalid object key")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("duplicate field")
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		values[key] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return values, nil
}

func exactFields(values map[string]json.RawMessage, required []string) error {
	if len(values) != len(required) {
		return errors.New("incorrect fields")
	}
	for _, field := range required {
		if _, ok := values[field]; !ok {
			return errors.New("missing field " + field)
		}
	}
	return nil
}

func stringValue(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errors.New("field must be a string")
	}
	return value, nil
}

func uintValue(raw json.RawMessage, max uint64) (uint64, error) {
	text := string(raw)
	if !number.MatchString(text) {
		return 0, errors.New("field must be a canonical non-negative integer")
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || value > max {
		return 0, errors.New("integer outside allowed range")
	}
	return value, nil
}

func (n *Node) outbound(ctx context.Context, method, target string, body []byte) (*http.Response, error) {
	if n.lag {
		if mrand.Float64() < simulatedLossProbability {
			return nil, errors.New("simulated outgoing loss")
		}
		select {
		case <-time.After(simulatedLagDelay()):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	if n.lag {
		if mrand.Float64() < simulatedLossProbability {
			response.Body.Close()
			return nil, errors.New("simulated response loss")
		}
		select {
		case <-time.After(simulatedLagDelay()):
		case <-ctx.Done():
			response.Body.Close()
			return nil, ctx.Err()
		}
	}
	return response, nil
}

func simulatedLagDelay() time.Duration {
	return simulatedLagMin + time.Duration(mrand.IntN(int(simulatedLagMax-simulatedLagMin)+1))
}

func (n *Node) broadcastTransaction(tx Transaction) {
	body, _ := json.Marshal(tx)
	for _, peer := range n.peers {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		response, err := n.outbound(ctx, http.MethodPost, peer+"/transactions", body)
		if response != nil {
			response.Body.Close()
		}
		cancel()
		_ = err // Best-effort gossip; later blocks carry confirmed transactions.
	}
}

func (n *Node) broadcastBlock(block Block) {
	body, _ := json.Marshal(block)
	for _, peer := range n.peers {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		response, err := n.outbound(ctx, http.MethodPost, peer+"/blocks", body)
		if response != nil {
			response.Body.Close()
		}
		cancel()
		_ = err
	}
}

func (n *Node) periodicSync() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		n.syncAll()
	}
}

func (n *Node) syncAll() {
	for _, peer := range n.peers {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		response, err := n.outbound(ctx, http.MethodGet, peer+"/tip", nil)
		if err != nil {
			cancel()
			continue
		}
		var tip struct {
			Height json.RawMessage `json:"height"`
			Hash   string          `json:"hash"`
		}
		err = json.NewDecoder(response.Body).Decode(&tip)
		response.Body.Close()
		cancel()
		if err != nil || !hex64.MatchString(tip.Hash) {
			continue
		}
		n.mu.RLock()
		_, have := n.blocks[tip.Hash]
		n.mu.RUnlock()
		if !have {
			n.fetchChainFromPeer(peer, tip.Hash)
		}
	}
}

func (n *Node) fetchChain(hash string) {
	for _, peer := range n.peers {
		n.fetchChainFromPeer(peer, hash)
		n.mu.RLock()
		_, have := n.blocks[hash]
		n.mu.RUnlock()
		if have {
			return
		}
	}
}

// Fetch parents first, then submit the resulting oldest-to-newest chain to
// the normal validator. A 404 or timeout simply tries the next peer later.
func (n *Node) fetchChainFromPeer(peer, hash string) {
	var descendants []Block
	for hash != genesisHash {
		n.mu.RLock()
		_, known := n.blocks[hash]
		n.mu.RUnlock()
		if known {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		response, err := n.outbound(ctx, http.MethodGet, peer+"/blocks/"+hash, nil)
		if err != nil || response.StatusCode != http.StatusOK {
			if response != nil {
				response.Body.Close()
			}
			cancel()
			return
		}
		block, decodeErr := decodeBlock(response.Body)
		response.Body.Close()
		cancel()
		if decodeErr != nil || hashBlock(block) != hash {
			return
		}
		descendants = append(descendants, block)
		hash = block.PrevHash
	}
	for i := len(descendants) - 1; i >= 0; i-- {
		n.mu.Lock()
		_, _, _ = n.acceptBlockLocked(descendants[i])
		n.mu.Unlock()
	}
}

func (n *Node) saveLocked() error {
	if n.dataPath == "" {
		return nil
	}
	blocks := make([]Block, 0, len(n.blocks)-1)
	for hash, stored := range n.blocks {
		if hash != genesisHash {
			blocks = append(blocks, stored.Block)
		}
	}
	slices.SortFunc(blocks, func(a, b Block) int { return int(a.Height) - int(b.Height) })
	data, err := json.MarshalIndent(diskData{Blocks: blocks, Mempool: n.mempool, PrivateKey: hex.EncodeToString(n.privateKey)}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(n.dataPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	temp := n.dataPath + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, n.dataPath)
}

func (n *Node) load() error {
	if n.dataPath == "" {
		return nil
	}
	data, err := os.ReadFile(n.dataPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk diskData
	if err := json.Unmarshal(data, &disk); err != nil {
		return err
	}
	if disk.PrivateKey != "" {
		privateKey, err := hex.DecodeString(disk.PrivateKey)
		if err != nil || len(privateKey) != ed25519.PrivateKeySize {
			return errors.New("invalid private key in local state")
		}
		n.privateKey = ed25519.PrivateKey(privateKey)
		n.miner = hex.EncodeToString(n.privateKey.Public().(ed25519.PublicKey))
	}
	// Parents can be in any order in the stored list, so retry until no block
	// can be attached. Invalid persisted blocks are never trusted.
	pending := slices.Clone(disk.Blocks)
	for len(pending) > 0 {
		next := pending[:0]
		progress := false
		for _, block := range pending {
			_, missing, err := n.acceptBlockLocked(block)
			if err != nil {
				continue
			}
			if missing {
				next = append(next, block)
			} else {
				progress = true
			}
		}
		if !progress {
			break
		}
		pending = next
	}
	n.mempool = nil
	for _, tx := range disk.Mempool {
		state := cloneState(n.blocks[n.tip].State)
		for _, queued := range n.mempool {
			_ = applyTransaction(&state, queued)
		}
		if applyTransaction(&state, tx) == nil {
			n.mempool = append(n.mempool, tx)
		}
	}
	return nil
}

// ensurePrivateKey preserves the node identity across restarts while allowing
// state files created before private-key persistence to remain usable.
func (n *Node) ensurePrivateKey() error {
	if len(n.privateKey) == ed25519.PrivateKeySize {
		return nil
	}
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return err
	}
	n.privateKey = privateKey
	n.miner = hex.EncodeToString(publicKey)
	return n.saveLocked()
}

// A small, self-contained implementation of the protocol described in the
// project brief. It deliberately uses only the Go standard library.

func Run() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	peersValue := flag.String("peers", "", "comma-separated peer base URLs")
	difficulty := flag.Int("difficulty", defaultDifficulty, "required leading zero bits (0-256)")
	dataPath := flag.String("data", "node-state.json", "local state file; empty disables persistence")
	noMine := flag.Bool("no-mine", false, "serve and synchronize but do not mine")
	noLag := flag.Bool("no-lag", false, "disable simulated outgoing network lag/loss")
	flag.Parse()

	if *difficulty < 0 || *difficulty > sha256.Size*8 {
		log.Fatal("difficulty must be between 0 and 256")
	}
	n := newNode("", *difficulty, parsePeers(*peersValue), !*noLag, *dataPath)
	if err := n.load(); err != nil {
		log.Fatalf("load local state: %v", err)
	}
	if err := n.ensurePrivateKey(); err != nil {
		log.Fatalf("initialize miner key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", n.handleCanvas)
	mux.HandleFunc("POST /canvas/transactions", n.handleCanvasTransaction)
	mux.HandleFunc("GET /tip", n.handleTip)
	mux.HandleFunc("GET /blocks/{hash}", n.handleGetBlock)
	mux.HandleFunc("POST /transactions", n.handleTransaction)
	mux.HandleFunc("POST /blocks", n.handleBlock)

	go n.syncAll()
	go n.periodicSync()
	if !*noMine {
		go n.mineForever()
	}

	log.Printf("node %s: miner=%s difficulty=%d peers=%d", *addr, n.miner, n.difficulty, len(n.peers))
	log.Fatal(http.ListenAndServe(*addr, mux))
}
