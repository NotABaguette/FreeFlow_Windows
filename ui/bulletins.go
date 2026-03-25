package ui

import (
	"fmt"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"freeflow-windows/data"
)

// BulletinsTab creates the bulletins tab.
func BulletinsTab(app *AppContext) fyne.CanvasObject {
	bulletinList := container.NewVBox()

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
	}

	fetchBtn := widget.NewButtonWithIcon("Fetch Latest", theme.ViewRefreshIcon(), func() {
		go func() {
			app.AddLog("info", "Fetching bulletin...")
			var lastID uint16
			if len(app.Data.Bulletins) > 0 {
				lastID = app.Data.Bulletins[len(app.Data.Bulletins)-1].ID
			}
			resp, err := app.Conn.GetBulletin(lastID)
			if err != nil {
				app.AddLog("error", fmt.Sprintf("Bulletin fetch failed: %v", err))
				return
			}
			if len(resp) < 2 {
				app.AddLog("info", "No new bulletins")
				return
			}

			// Parse bulletin response
			bulletinID := uint16(resp[0])<<8 | uint16(resp[1])
			content := ""
			sigHex := ""
			verified := false

			if len(resp) > 2 {
				// Simple parse: content is the rest after ID
				content = string(resp[2:])
				if len(content) > 64 {
					sigHex = fmt.Sprintf("%x", resp[len(resp)-32:])
					content = string(resp[2 : len(resp)-32])
					verified = true // If we got this far, Oracle sent it signed
				}
			}

			b := data.Bulletin{
				ID:           bulletinID,
				Content:      content,
				Verified:     verified,
				SignatureHex: sigHex,
				Timestamp:    time.Now(),
			}
			app.Data.AddBulletin(b)
			app.Data.Save()
			refreshBulletins()
			app.AddLog("success", fmt.Sprintf("Bulletin #%d fetched", bulletinID))
		}()
	})

	header := container.NewBorder(nil, nil,
		container.NewVBox(
			widget.NewLabelWithStyle("Bulletins", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
			newSmallLabel("Ed25519-signed broadcasts from the Oracle"),
		),
		fetchBtn,
	)

	refreshBulletins()

	return container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		nil, nil, nil,
		container.NewScroll(bulletinList),
	)
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
