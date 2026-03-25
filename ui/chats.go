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

// ensure identity package is available for sendMessage


// ChatsTab creates the chats tab with conversation list + messenger view.
func ChatsTab(app *AppContext) fyne.CanvasObject {
	// Selected contact fingerprint
	var selectedFP string
	var chatArea *fyne.Container
	var messageList *widget.List
	var messageEntry *widget.Entry
	var sendBtn *widget.Button
	var messages []data.ChatMessage

	// E2E encryption notice
	encNotice := canvas.NewText("Messages are end-to-end encrypted with X25519 + ChaCha20-Poly1305", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	encNotice.TextSize = 11
	encNotice.Alignment = fyne.TextAlignCenter

	lockIcon := canvas.NewText("[ Encrypted ]", color.NRGBA{R: 0, G: 180, B: 0, A: 255})
	lockIcon.TextSize = 11
	lockIcon.Alignment = fyne.TextAlignCenter

	// Message list widget
	messageList = widget.NewList(
		func() int {
			return len(messages) + 1 // +1 for encryption notice
		},
		func() fyne.CanvasObject {
			// Template for a message bubble
			msgText := widget.NewLabel("Message text here that can be quite long")
			msgText.Wrapping = fyne.TextWrapWord
			timeLabel := canvas.NewText("00:00", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
			timeLabel.TextSize = 10
			statusLabel := canvas.NewText("", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
			statusLabel.TextSize = 10

			bubble := container.NewVBox(msgText, container.NewHBox(timeLabel, statusLabel))
			bg := canvas.NewRectangle(color.NRGBA{R: 60, G: 60, B: 60, A: 255})
			bg.CornerRadius = 12

			return container.NewStack(bg, container.NewPadded(bubble))
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			stack := obj.(*fyne.Container)
			bg := stack.Objects[0].(*canvas.Rectangle)
			padded := stack.Objects[1].(*fyne.Container)
			box := padded.Objects[0].(*fyne.Container)
			msgLabel := box.Objects[0].(*widget.Label)
			hbox := box.Objects[1].(*fyne.Container)
			timeLabel := hbox.Objects[0].(*canvas.Text)
			statusLabel := hbox.Objects[1].(*canvas.Text)

			if id == 0 {
				// Encryption notice row
				msgLabel.SetText("End-to-end encrypted with X25519 + ChaCha20-Poly1305")
				msgLabel.Alignment = fyne.TextAlignCenter
				bg.FillColor = color.NRGBA{R: 40, G: 40, B: 40, A: 255}
				bg.Refresh()
				timeLabel.Text = ""
				timeLabel.Refresh()
				statusLabel.Text = ""
				statusLabel.Refresh()
				return
			}

			idx := id - 1
			if idx >= len(messages) {
				return
			}
			msg := messages[idx]
			msgLabel.SetText(msg.Text)

			timeLabel.Text = msg.Timestamp.Format("15:04")
			timeLabel.Refresh()

			if msg.Direction == data.DirSent {
				// Blue bubble for sent
				bg.FillColor = color.NRGBA{R: 0, G: 122, B: 255, A: 255}
				msgLabel.Alignment = fyne.TextAlignTrailing
				switch msg.Status {
				case data.StatusSending:
					statusLabel.Text = " [sending]"
					statusLabel.Color = color.NRGBA{R: 200, G: 200, B: 200, A: 200}
				case data.StatusSent:
					statusLabel.Text = " [sent]"
					statusLabel.Color = color.NRGBA{R: 200, G: 200, B: 200, A: 200}
				case data.StatusDelivered:
					statusLabel.Text = " [delivered]"
					statusLabel.Color = color.NRGBA{R: 0, G: 200, B: 0, A: 255}
				case data.StatusFailed:
					statusLabel.Text = " [failed]"
					statusLabel.Color = color.NRGBA{R: 255, G: 0, B: 0, A: 255}
				}
			} else {
				// Gray bubble for received
				bg.FillColor = color.NRGBA{R: 60, G: 60, B: 60, A: 255}
				msgLabel.Alignment = fyne.TextAlignLeading
				statusLabel.Text = ""
			}
			bg.Refresh()
			statusLabel.Refresh()
		},
	)

	refreshMessages := func() {
		if selectedFP != "" {
			messages = app.Data.GetMessages(selectedFP)
		} else {
			messages = nil
		}
		messageList.Refresh()
		// Scroll to bottom
		if len(messages) > 0 {
			messageList.ScrollToBottom()
		}
	}

	// Message input
	messageEntry = widget.NewEntry()
	messageEntry.SetPlaceHolder("Message...")
	messageEntry.OnSubmitted = func(s string) {
		if s == "" || selectedFP == "" {
			return
		}
		sendMessage(app, selectedFP, s, refreshMessages)
		messageEntry.SetText("")
	}

	sendBtn = widget.NewButtonWithIcon("", theme.MailSendIcon(), func() {
		text := messageEntry.Text
		if text == "" || selectedFP == "" {
			return
		}
		sendMessage(app, selectedFP, text, refreshMessages)
		messageEntry.SetText("")
	})

	inputBar := container.NewBorder(nil, nil, nil, sendBtn, messageEntry)

	// Placeholder when no chat selected
	noChat := container.NewCenter(
		container.NewVBox(
			widget.NewLabelWithStyle("FreeFlow", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true}),
			widget.NewLabelWithStyle("Select a conversation", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
			lockIcon,
			encNotice,
		),
	)

	// Chat header
	chatHeaderName := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
	chatHeaderFP := canvas.NewText("", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	chatHeaderFP.TextSize = 11
	chatHeader := container.NewVBox(
		container.NewHBox(chatHeaderName, layout.NewSpacer()),
		chatHeaderFP,
		widget.NewSeparator(),
	)

	chatArea = container.NewBorder(chatHeader, inputBar, nil, nil, messageList)
	chatArea.Hide()

	// Conversation list
	contacts := app.Contacts.List()
	convList := widget.NewList(
		func() int {
			contacts = app.Contacts.List()
			return len(contacts)
		},
		func() fyne.CanvasObject {
			name := widget.NewLabelWithStyle("Contact Name", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
			preview := canvas.NewText("Last message...", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
			preview.TextSize = 12
			badge := canvas.NewText("", color.NRGBA{R: 0, G: 122, B: 255, A: 255})
			badge.TextSize = 12
			badge.TextStyle = fyne.TextStyle{Bold: true}
			return container.NewBorder(nil, nil, nil, badge, container.NewVBox(name, preview))
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			contacts = app.Contacts.List()
			if id >= len(contacts) {
				return
			}
			c := contacts[id]
			border := obj.(*fyne.Container)
			vbox := border.Objects[0].(*fyne.Container)
			name := vbox.Objects[0].(*widget.Label)
			preview := vbox.Objects[1].(*canvas.Text)
			badge := border.Objects[1].(*canvas.Text)

			name.SetText(c.DisplayName)

			msgs := app.Data.GetMessages(c.FingerprintHex())
			if len(msgs) > 0 {
				last := msgs[len(msgs)-1]
				if len(last.Text) > 30 {
					preview.Text = last.Text[:30] + "..."
				} else {
					preview.Text = last.Text
				}
			} else {
				preview.Text = "No messages yet"
			}
			preview.Refresh()

			app.Data.ClearUnread("") // just access for read lock
			count := 0
			if uc, ok := app.Data.UnreadCounts[c.FingerprintHex()]; ok {
				count = uc
			}
			if count > 0 {
				badge.Text = fmt.Sprintf("(%d)", count)
			} else {
				badge.Text = ""
			}
			badge.Refresh()
		},
	)

	convList.OnSelected = func(id widget.ListItemID) {
		contacts = app.Contacts.List()
		if id >= len(contacts) {
			return
		}
		c := contacts[id]
		selectedFP = c.FingerprintHex()
		chatHeaderName.SetText(c.DisplayName)
		chatHeaderFP.Text = c.FingerprintHex()
		chatHeaderFP.Refresh()
		app.Data.ClearUnread(selectedFP)
		noChat.Hide()
		chatArea.Show()
		refreshMessages()
	}

	// Sync inbox button
	syncBtn := widget.NewButtonWithIcon("Sync Inbox", theme.ViewRefreshIcon(), func() {
		go func() {
			app.AddLog("info", "Syncing inbox...")
			text, sender, err := app.Conn.PollMessages(app.Contacts)
			if err != nil {
				app.AddLog("error", fmt.Sprintf("Inbox sync failed: %v", err))
				return
			}
			if sender == nil {
				app.AddLog("info", "No new messages")
				return
			}
			msg := data.ChatMessage{
				ID:        fmt.Sprintf("recv-%d", time.Now().UnixNano()),
				Text:      text,
				Direction: data.DirReceived,
				Status:    data.StatusDelivered,
				Timestamp: time.Now(),
			}
			app.Data.AddMessage(sender.FingerprintHex(), msg)
			app.Data.IncrementUnread(sender.FingerprintHex())
			app.Data.Save()
			convList.Refresh()
			if selectedFP == sender.FingerprintHex() {
				refreshMessages()
			}
		}()
	})

	convHeader := container.NewBorder(nil, nil,
		widget.NewLabelWithStyle("Messages", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		syncBtn,
	)

	leftPanel := container.NewBorder(
		container.NewVBox(convHeader, widget.NewSeparator()),
		nil, nil, nil,
		convList,
	)

	rightPanel := container.NewStack(noChat, chatArea)

	// Register refresh callback
	app.OnChatRefresh = func() {
		convList.Refresh()
		refreshMessages()
	}

	split := container.NewHSplit(leftPanel, rightPanel)
	split.SetOffset(0.3)
	return split
}

func sendMessage(app *AppContext, contactFP, text string, refresh func()) {
	contact := app.Contacts.FindByFingerprint(contactFP)
	if contact == nil {
		app.AddLog("error", "Contact not found")
		return
	}

	msgID := fmt.Sprintf("sent-%d", time.Now().UnixNano())
	msg := data.ChatMessage{
		ID:        msgID,
		Text:      text,
		Direction: data.DirSent,
		Status:    data.StatusSending,
		Timestamp: time.Now(),
	}
	app.Data.AddMessage(contactFP, msg)
	app.Data.Save()
	refresh()

	go func() {
		_, err := app.Conn.SendMessage(text, contact)
		if err != nil {
			app.Data.UpdateMessageStatus(msgID, data.StatusFailed)
			app.AddLog("error", fmt.Sprintf("Send failed: %v", err))
		} else {
			app.Data.UpdateMessageStatus(msgID, data.StatusSent)
		}
		app.Data.Save()
		refresh()
	}()
}
