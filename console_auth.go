package main

// The console's Basic auth page: the basic_auth groups, their users and the
// serve entries that use each, and changes to them. A password typed here is
// hashed in the proxy (argon2id) before it is written; no password or hash
// is ever sent back to the page.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

type authUserView struct {
	Name     string `json:"name"`
	Plain    bool   `json:"plain"` // written with password_plain: setting a password hashes it
	Disabled bool   `json:"disabled"`
	Expires  string `json:"expires,omitempty"` // when it stops working, RFC 3339 UTC; "" = never
	Expired  bool   `json:"expired"`
}

type authUseView struct {
	Rule   string `json:"rule"` // the rule's domain
	Line   int    `json:"line"`
	Prefix string `json:"prefix"`
}

type authGroupView struct {
	Name   string         `json:"name"`
	Line   int            `json:"line"`
	Users  []authUserView `json:"users"`
	UsedBy []authUseView  `json:"usedBy"`
}

// authGroupViews lists cfg's basic_auth groups, by name.
func authGroupViews(cfg *Config) []authGroupView {
	out := []authGroupView{}
	if cfg == nil {
		return out
	}
	names := make([]string, 0, len(cfg.BasicAuth))
	for n := range cfg.BasicAuth {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		a := cfg.BasicAuth[n]
		v := authGroupView{Name: n, Line: a.Line, Users: []authUserView{}, UsedBy: []authUseView{}}
		users := make([]string, 0, len(a.Users))
		for u := range a.Users {
			users = append(users, u)
		}
		slices.Sort(users)
		for _, u := range users {
			cred := a.Users[u]
			uv := authUserView{Name: u, Plain: cred.hash == "", Disabled: cred.disabled}
			if !cred.expires.IsZero() {
				uv.Expires, uv.Expired = cred.expires.UTC().Format(time.RFC3339), !time.Now().Before(cred.expires)
			}
			v.Users = append(v.Users, uv)
		}
		for _, r := range cfg.Rules {
			for _, s := range r.Routes {
				if s.BasicAuth == n {
					v.UsedBy = append(v.UsedBy, authUseView{Rule: r.Source, Line: r.Line, Prefix: s.Prefix})
				}
			}
		}
		out = append(out, v)
	}
	return out
}

func (c *Console) authList(w http.ResponseWriter, r *http.Request) {
	pf := c.configFile()
	writeJSON(w, 200, map[string]any{"ok": true, "groups": authGroupViews(pf.cfg), "file": pf.view})
}

// authSave makes one change to the groups, through the same checks as every
// other save: the file must be the version the page loaded, and the result
// must load.
func (c *Console) authSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		authEdit
		BaseHash, BaseMtime string
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	req.Group, req.NewName, req.User = strings.TrimSpace(req.Group), strings.TrimSpace(req.NewName), strings.TrimSpace(req.User)
	configFileMu.Lock()
	defer configFileMu.Unlock()
	onDisk, ver, err := c.readConfig()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	if req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash {
		fail(w, http.StatusConflict, "not saved: the config file changed after this page loaded it. The page now shows the current version; try again")
		return
	}
	full, notes, err := editBasicAuth(string(onDisk), req.authEdit, hashPassword)
	if err == nil {
		var cfg *Config
		if cfg, err = c.check(full); err == nil {
			for _, n := range notes {
				logf("console: %s", n)
			}
			what := map[string]string{"add_group": "basic_auth group %s added", "rename_group": "basic_auth group %s renamed",
				"delete_group": "basic_auth group %s deleted", "add_user": "basic_auth %s: user added", "delete_user": "basic_auth %s: user deleted",
				"set_password": "basic_auth %s: password set", "set_disabled": "basic_auth %s: user enabled or disabled",
				"set_expiry": "basic_auth %s: user's expiry set"}[req.Op]
			c.commit(w, r, onDisk, full, cfg, fmt.Sprintf(what, req.Group))
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
}
