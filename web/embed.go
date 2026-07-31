// Package web embeds the management UI assets into the binary so the registry
// ships as a single file with no runtime asset directory.
package web

import "embed"

//go:embed index.html app.js style.css
var Files embed.FS
