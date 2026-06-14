// Command mkicon renders the BreachHound application icon (a paw on a dark
// rounded tile) and writes it as PNG and a multi-size ICO under
// cmd/breachhound-gui/assets. Run from the repo root: `go run ./tools/mkicon`.
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
)

const base = 256

var (
	bg   = color.RGBA{0x11, 0x16, 0x1d, 0xff}
	teal = color.RGBA{0x2d, 0xd4, 0xbf, 0xff}
)

func main() {
	img := render()

	var pngBig bytes.Buffer
	if err := png.Encode(&pngBig, img); err != nil {
		log.Fatal(err)
	}
	mustWrite("cmd/breachhound-gui/assets/icon.png", pngBig.Bytes())

	var entries []icoEntry
	for _, s := range []int{256, 48, 32, 16} {
		var b bytes.Buffer
		if err := png.Encode(&b, downscale(img, s)); err != nil {
			log.Fatal(err)
		}
		entries = append(entries, icoEntry{size: s, data: b.Bytes()})
	}
	mustWrite("cmd/breachhound-gui/assets/icon.ico", buildICO(entries))
	log.Println("wrote icon.png and a multi-size icon.ico")
}

func render() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, base, base))
	for y := 0; y < base; y++ {
		for x := 0; x < base; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			if cov := roundedRectCoverage(fx, fy, base, base, 56); cov > 0 {
				blend(img, x, y, bg, cov)
			}
			cov := ellipseCoverage(fx, fy, 134, 166, 46, 36)
			cov = maxf(cov, circleCoverage(fx, fy, 90, 122, 17))
			cov = maxf(cov, circleCoverage(fx, fy, 118, 102, 18))
			cov = maxf(cov, circleCoverage(fx, fy, 150, 102, 18))
			cov = maxf(cov, circleCoverage(fx, fy, 178, 122, 17))
			if cov > 0 {
				blend(img, x, y, teal, cov)
			}
		}
	}
	return img
}

// downscale area-averages the base image down to an n×n image.
func downscale(src *image.RGBA, n int) *image.RGBA {
	if n == base {
		return src
	}
	dst := image.NewRGBA(image.Rect(0, 0, n, n))
	scale := float64(base) / float64(n)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var r, g, b, a, cnt float64
			x0, y0 := int(float64(x)*scale), int(float64(y)*scale)
			x1, y1 := int(float64(x+1)*scale), int(float64(y+1)*scale)
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					c := src.RGBAAt(sx, sy)
					af := float64(c.A) / 255
					r += float64(c.R) * af
					g += float64(c.G) * af
					b += float64(c.B) * af
					a += float64(c.A)
					cnt++
				}
			}
			if cnt == 0 {
				continue
			}
			aa := a / cnt
			if aa == 0 {
				continue
			}
			norm := 255 / a
			dst.SetRGBA(x, y, color.RGBA{
				uint8(math.Round(r * norm)),
				uint8(math.Round(g * norm)),
				uint8(math.Round(b * norm)),
				uint8(math.Round(aa)),
			})
		}
	}
	return dst
}

func blend(img *image.RGBA, x, y int, src color.RGBA, cov float64) {
	if cov <= 0 {
		return
	}
	if cov > 1 {
		cov = 1
	}
	dst := img.RGBAAt(x, y)
	da := float64(dst.A) / 255
	outA := cov + da*(1-cov)
	if outA <= 0 {
		return
	}
	mix := func(s, d uint8) uint8 {
		sv, dv := float64(s)/255, float64(d)/255
		o := (sv*cov + dv*da*(1-cov)) / outA
		return uint8(math.Round(o * 255))
	}
	img.SetRGBA(x, y, color.RGBA{mix(src.R, dst.R), mix(src.G, dst.G), mix(src.B, dst.B), uint8(math.Round(outA * 255))})
}

func circleCoverage(x, y, cx, cy, r float64) float64 {
	return clamp01(0.5 + (r - math.Hypot(x-cx, y-cy)))
}

func ellipseCoverage(x, y, cx, cy, rx, ry float64) float64 {
	d := math.Hypot((x-cx)/rx, (y-cy)/ry)
	return clamp01(0.5 + (1-d)*math.Min(rx, ry))
}

func roundedRectCoverage(x, y, w, h, r float64) float64 {
	var d float64
	switch {
	case x < r && y < r:
		d = math.Hypot(x-r, y-r) - r
	case x > w-r && y < r:
		d = math.Hypot(x-(w-r), y-r) - r
	case x < r && y > h-r:
		d = math.Hypot(x-r, y-(h-r)) - r
	case x > w-r && y > h-r:
		d = math.Hypot(x-(w-r), y-(h-r)) - r
	default:
		if x >= 0 && x <= w && y >= 0 && y <= h {
			return 1
		}
		return 0
	}
	return clamp01(0.5 - d)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

type icoEntry struct {
	size int
	data []byte
}

func buildICO(entries []icoEntry) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(1))
	binary.Write(&b, binary.LittleEndian, uint16(len(entries)))
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		dim := byte(e.size)
		if e.size >= 256 {
			dim = 0
		}
		b.WriteByte(dim)
		b.WriteByte(dim)
		b.WriteByte(0)
		b.WriteByte(0)
		binary.Write(&b, binary.LittleEndian, uint16(1))
		binary.Write(&b, binary.LittleEndian, uint16(32))
		binary.Write(&b, binary.LittleEndian, uint32(len(e.data)))
		binary.Write(&b, binary.LittleEndian, uint32(offset))
		offset += len(e.data)
	}
	for _, e := range entries {
		b.Write(e.data)
	}
	return b.Bytes()
}

func mustWrite(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatal(err)
	}
}
