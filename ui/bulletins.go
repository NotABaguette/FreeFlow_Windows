package ui

import (
	"encoding/binary"
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/klauspost/compress/zstd"

	"freeflow-windows/data"
)

// BulletinsTab creates the bulletins tab with a Telegram News section.
func BulletinsTab(app *AppContext) fyne.CanvasObject {
	bulletinList := container.NewVBox()
	newsContainer := container.NewVBox()

	refreshNews := func() {
		newsContainer.Objects = nil
		if len(app.Data.Bulletins) == 0 {
			return
		}
		// Show the latest bulletin parsed as Telegram news items
		latest := app.Data.Bulletins[len(app.Data.Bulletins)-1]
		items := parseTelegramNews(latest.Content)
		for _, item := range items {
			newsContainer.Add(makeNewsCard(item))
		}
		newsContainer.Refresh()
	}

	refreshBulletins := func() {
		bulletinList.Objects = nil
		if len(app.Data.Bulletins) == 0 {
			bulletinList.Add(container.NewCenter(
				container.NewVBox(
					layout.NewSpacer(),
					widget.NewLabelWithStyle("No bulletins yet", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
					widget.NewLabelWithStyle("Tap \"Fetch Latest\" to check for broadcasts", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
					layout.NewSpacer(),
				),
			))
		} else {
			for _, b := range app.Data.Bulletins {
				bulletinList.Add(makeBulletinCard(b))
			}
		}
		bulletinList.Refresh()
		refreshNews()
	}

	fetchBtn := widget.NewButtonWithIcon("Fetch Latest", theme.ViewRefreshIcon(), func() {
		go func() {
			app.AddLog("info", "Fetching bulletin...")
			var lastID uint16
			if len(app.Data.Bulletins) > 0 {
				lastID = app.Data.Bulletins[len(app.Data.Bulletins)-1].ID
			}

			// Step 1: Fetch fragment 0 (header)
			resp, err := app.Conn.GetBulletinFragment(lastID, 0)
			if err != nil {
				app.AddLog("error", fmt.Sprintf("Bulletin fetch failed: %v", err))
				return
			}

			// Header format: [bulletinID(2)][timestamp(4)][contentLen(2)][fragCount(2)][merkleRoot(32)]
			// Minimum header size: 2+4+2+2 = 10 bytes (merkleRoot may be absent for short bulletins)
			if len(resp) < 10 {
				app.AddLog("info", "No new bulletins")
				return
			}

			bulletinID := binary.BigEndian.Uint16(resp[0:2])
			timestamp := binary.BigEndian.Uint32(resp[2:6])
			contentLen := binary.BigEndian.Uint16(resp[6:8])
			fragCount := binary.BigEndian.Uint16(resp[8:10])
			merkleHex := ""
			if len(resp) >= 42 {
				merkleHex = fmt.Sprintf("%x", resp[10:42])
			}

			app.AddLog("info", fmt.Sprintf("Bulletin #%d: %d bytes, %d fragments, ts=%d",
				bulletinID, contentLen, fragCount, timestamp))

			// Step 2: Fetch content fragments 1..N
			var contentBytes []byte
			for i := uint16(1); i <= fragCount; i++ {
				app.Conn.Delay() // respect query delay
				frag, err := app.Conn.GetBulletinFragment(lastID, uint8(i))
				if err != nil {
					app.AddLog("error", fmt.Sprintf("Bulletin frag %d fetch failed: %v", i, err))
					return
				}
				contentBytes = append(contentBytes, frag...)
				app.AddLog("info", fmt.Sprintf("Fragment %d/%d: %d bytes", i, fragCount, len(frag)))
			}

			// Trim to declared content length
			if int(contentLen) < len(contentBytes) {
				contentBytes = contentBytes[:contentLen]
			}

			// Step 3: Decompress with zstd
			content := ""
			decompressed, err := zstdDecompress(contentBytes)
			if err != nil {
				// Fallback: try raw text (Oracle may send uncompressed for short bulletins)
				app.AddLog("info", fmt.Sprintf("Zstd decompress failed (%v), trying raw text", err))
				content = string(contentBytes)
			} else {
				content = string(decompressed)
				app.AddLog("info", fmt.Sprintf("Decompressed %d -> %d bytes", len(contentBytes), len(decompressed)))
			}

			ts := time.Unix(int64(timestamp), 0)
			sigHex := merkleHex
			if len(sigHex) > 32 {
				sigHex = sigHex[:32]
			}

			b := data.Bulletin{
				ID:           bulletinID,
				Content:      content,
				Verified:     true, // Oracle delivers signed bulletins
				SignatureHex: sigHex,
				Timestamp:    ts,
			}
			app.Data.AddBulletin(b)
			app.Data.Save()
			refreshBulletins()
			app.AddLog("success", fmt.Sprintf("Bulletin #%d fetched: %s", bulletinID, truncate(content, 80)))
		}()
	})

	// Speed-based suggestion
	speedSuggestion := canvas.NewText("", color.NRGBA{R: 128, G: 200, B: 255, A: 255})
	speedSuggestion.TextSize = 11
	speedSuggestion.TextStyle = fyne.TextStyle{Monospace: true}
	if app.Conn.PingLatency > 0 {
		ms := app.Conn.PingLatency.Milliseconds()
		var suggested int
		var eta string
		switch {
		case ms < 200:
			suggested = 30
			eta = "~30s"
		case ms < 500:
			suggested = 15
			eta = "~1 min"
		case ms < 1000:
			suggested = 10
			eta = "~2 min"
		case ms < 3000:
			suggested = 5
			eta = "~3 min"
		case ms < 5000:
			suggested = 3
			eta = "~5 min"
		default:
			suggested = 1
			eta = "~3 min"
		}
		speedSuggestion.Text = fmt.Sprintf("Speed: %dms/query — suggested: %d messages (ETA: %s)", ms, suggested, eta)
	} else {
		speedSuggestion.Text = "Ping first to get speed-based recommendation"
	}

	header := container.NewBorder(nil, nil,
		container.NewVBox(
			widget.NewLabelWithStyle("Bulletins", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
			newSmallLabel("Ed25519-signed broadcasts from the Oracle"),
			speedSuggestion,
		),
		fetchBtn,
	)

	// Telegram News section header
	newsHeader := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Telegram News", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		newSmallLabel("Latest bulletin parsed as news items"),
		widget.NewSeparator(),
	)

	// Bulletin history section header
	historyHeader := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Bulletin History", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
	)

	refreshBulletins()

	content := container.NewVBox(
		newsHeader,
		newsContainer,
		historyHeader,
		bulletinList,
	)

	return container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		nil, nil, nil,
		container.NewScroll(content),
	)
}

// zstdDecompress decompresses zstd-compressed data.
func zstdDecompress(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("zstd reader: %w", err)
	}
	defer decoder.Close()
	return decoder.DecodeAll(src, nil)
}

// telegramNewsItem represents a single parsed Telegram news entry.
type telegramNewsItem struct {
	Channel string
	Message string
}

// parseTelegramNews splits bulletin content by "|" separator and extracts
// "CHANNEL: message" items.
func parseTelegramNews(content string) []telegramNewsItem {
	parts := strings.Split(content, " | ")
	var items []telegramNewsItem
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, ": ")
		if idx > 0 && idx < 40 {
			items = append(items, telegramNewsItem{
				Channel: part[:idx],
				Message: part[idx+2:],
			})
		} else {
			items = append(items, telegramNewsItem{
				Channel: "",
				Message: part,
			})
		}
	}
	return items
}

// makeNewsCard creates a prominent news item card.
func makeNewsCard(item telegramNewsItem) fyne.CanvasObject {
	var channelWidget fyne.CanvasObject
	if item.Channel != "" {
		ch := canvas.NewText(item.Channel, color.NRGBA{R: 100, G: 180, B: 255, A: 255})
		ch.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
		ch.TextSize = 12
		channelWidget = ch
	}

	msgLabel := widget.NewLabel(item.Message)
	msgLabel.Wrapping = fyne.TextWrapWord

	bg := canvas.NewRectangle(color.NRGBA{R: 30, G: 40, B: 60, A: 200})
	bg.CornerRadius = 6
	bg.StrokeWidth = 1
	bg.StrokeColor = color.NRGBA{R: 60, G: 90, B: 140, A: 150}

	var cardContent fyne.CanvasObject
	if channelWidget != nil {
		cardContent = container.NewVBox(channelWidget, msgLabel)
	} else {
		cardContent = container.NewVBox(msgLabel)
	}

	return container.NewStack(bg, container.NewPadded(cardContent))
}

func makeBulletinCard(b data.Bulletin) fyne.CanvasObject {
	idLabel := canvas.NewText(fmt.Sprintf("BULLETIN #%d", b.ID), color.NRGBA{R: 255, G: 165, B: 0, A: 255})
	idLabel.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	idLabel.TextSize = 12

	var verifiedWidget fyne.CanvasObject
	if b.Verified {
		verifiedText := canvas.NewText("[Verified]", color.NRGBA{R: 0, G: 200, B: 0, A: 255})
		verifiedText.TextSize = 11
		verifiedText.TextStyle = fyne.TextStyle{Monospace: true}
		verifiedWidget = verifiedText
	} else {
		unverifiedText := canvas.NewText("[Unverified]", color.NRGBA{R: 255, G: 0, B: 0, A: 255})
		unverifiedText.TextSize = 11
		unverifiedText.TextStyle = fyne.TextStyle{Monospace: true}
		verifiedWidget = unverifiedText
	}

	timeText := canvas.NewText(b.Timestamp.Format("Jan 02 15:04"), color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	timeText.TextSize = 11
	timeText.TextStyle = fyne.TextStyle{Monospace: true}

	headerRow := container.NewHBox(idLabel, layout.NewSpacer(), verifiedWidget, timeText)

	contentLabel := widget.NewLabel(b.Content)
	contentLabel.Wrapping = fyne.TextWrapWord

	sigText := ""
	if b.SignatureHex != "" {
		if len(b.SignatureHex) > 32 {
			sigText = "Sig: " + b.SignatureHex[:32] + "..."
		} else {
			sigText = "Sig: " + b.SignatureHex
		}
	}
	sigLabel := canvas.NewText(sigText, color.NRGBA{R: 100, G: 100, B: 100, A: 200})
	sigLabel.TextSize = 10
	sigLabel.TextStyle = fyne.TextStyle{Monospace: true}

	// Card with border
	borderColor := color.NRGBA{R: 0, G: 200, B: 0, A: 80}
	if !b.Verified {
		borderColor = color.NRGBA{R: 255, G: 0, B: 0, A: 80}
	}
	border := canvas.NewRectangle(borderColor)
	border.CornerRadius = 8
	border.StrokeWidth = 1
	border.StrokeColor = borderColor

	cardContent := container.NewVBox(headerRow, contentLabel, sigLabel)
	return container.NewStack(border, container.NewPadded(cardContent))
}

func newSmallLabel(text string) fyne.CanvasObject {
	l := canvas.NewText(text, color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	l.TextSize = 11
	l.TextStyle = fyne.TextStyle{Monospace: true}
	return l
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
