package main

// A folder's listing, for static_content with directory_listing: true. One
// self-contained page (no request leaves it: the styles and the script for
// sorting and filtering are inline), light or dark with the browser.

import (
	_ "embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// maxListing caps the entries one listing shows; the rest are counted.
const maxListing = 5000

//go:embed serve_listing.html
var listingHTML string

var listingPage = template.Must(template.New("listing").Parse(listingHTML))

type listingEntry struct {
	Name     string
	Href     string // relative, escaped
	Dir      bool
	Size     int64
	SizeText string
	Kind     string // folder, image, video, audio, archive, code, text, doc, other
	Ext      string // up to 4 letters, for the file's badge
	Modified time.Time
}

type listingCrumb struct {
	Name, Href string
}

type listingData struct {
	Title   string
	Host    string
	Crumbs  []listingCrumb
	Parent  bool
	Entries []listingEntry
	Folders int
	Files   int
	Total   string
	Hidden  int // more than maxListing: not shown
}

// serveListing writes the listing of name, a folder in root, for r.
func serveListing(w http.ResponseWriter, r *http.Request, root *os.Root, name string) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	all, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return err
	}
	d := listingData{Host: r.Host}
	var total int64
	for _, e := range all {
		n := e.Name()
		if strings.HasPrefix(n, ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			// Followed only inside base_dir, as the file server does.
			if info, err = root.Stat(path.Join(name, n)); err != nil {
				continue
			}
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		if len(d.Entries) >= maxListing {
			d.Hidden++
			continue
		}
		le := listingEntry{Name: n, Dir: info.IsDir(), Modified: info.ModTime().UTC()}
		href := (&urlPath{n}).String()
		if le.Dir {
			le.Href, le.Kind = href+"/", "folder"
			d.Folders++
		} else {
			le.Href, le.Size, le.SizeText = href, info.Size(), humanBytes(info.Size())
			le.Kind, le.Ext = fileKind(n)
			total += info.Size()
			d.Files++
		}
		d.Entries = append(d.Entries, le)
	}
	sort.SliceStable(d.Entries, func(i, j int) bool {
		a, b := d.Entries[i], d.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	d.Total = humanBytes(total)

	// The path as links, each part to its folder.
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if parts[0] == "" {
		parts = nil
	}
	d.Crumbs = append(d.Crumbs, listingCrumb{Name: r.Host, Href: "/"})
	at := "/"
	for _, p := range parts {
		at += (&urlPath{p}).String() + "/"
		d.Crumbs = append(d.Crumbs, listingCrumb{Name: p, Href: at})
	}
	d.Parent = len(parts) > 0
	d.Title = "/" + strings.Join(parts, "/")
	if len(parts) > 0 {
		d.Title += "/"
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")
	if r.Method == http.MethodHead {
		return nil
	}
	return listingPage.Execute(w, d)
}

// urlPath escapes one path part for an href.
type urlPath struct{ s string }

func (p *urlPath) String() string {
	var b strings.Builder
	for i := 0; i < len(p.s); i++ {
		c := p.s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~!$&'()*+,;=:@", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

var fileKinds = map[string]string{}

func init() {
	for kind, exts := range map[string]string{
		"image":   "png jpg jpeg gif webp svg avif bmp ico heic tif tiff",
		"video":   "mp4 mkv mov webm avi m4v wmv flv",
		"audio":   "mp3 flac wav ogg m4a aac opus",
		"archive": "zip tar gz tgz bz2 xz zst 7z rar iso dmg deb rpm apk",
		"code":    "go rs js ts jsx tsx py rb java c h cc cpp hpp cs php sh bash fish zsh ps1 swift kt lua sql html htm css scss json yaml yml toml xml wasm",
		"doc":     "pdf doc docx xls xlsx ppt pptx odt ods odp epub rtf",
		"text":    "txt md log csv tsv ini conf cfg env pem crt key",
	} {
		for _, e := range strings.Fields(exts) {
			fileKinds[e] = kind
		}
	}
}

// fileKind is a file's kind, by its extension, and that extension for its
// badge.
func fileKind(name string) (kind, ext string) {
	ext = strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))
	kind = fileKinds[ext]
	if kind == "" {
		kind = "other"
	}
	if len(ext) > 4 {
		ext = ext[:4]
	}
	return kind, ext
}
