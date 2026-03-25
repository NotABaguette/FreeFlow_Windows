package ui

import (
	"encoding/hex"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"freeflow-windows/data"
	"freeflow-windows/identity"
)

// ContactsTab creates the contacts tab.
func ContactsTab(app *AppContext) fyne.CanvasObject {
	var selectedContact *identity.Contact
	var detailArea *fyne.Container

	// Contact detail view
	detailName := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})
	detailFP := canvas.NewText("", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	detailFP.TextSize = 12
	detailFP.Alignment = fyne.TextAlignCenter

	detailPubKey := widget.NewEntry()
	detailPubKey.Disable()
	detailPubKey.MultiLine = true
	detailPubKey.Wrapping = fyne.TextWrapBreak

	fpLabel := widget.NewLabelWithStyle("Fingerprint:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	fpValue := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})

	pkLabel := widget.NewLabelWithStyle("Public Key:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})

	statsBox := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Statistics", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
	)

	msgCountLabel := widget.NewLabelWithStyle("Messages: 0", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	sentCountLabel := widget.NewLabelWithStyle("Sent: 0", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	recvCountLabel := widget.NewLabelWithStyle("Received: 0", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	statsBox.Add(msgCountLabel)
	statsBox.Add(sentCountLabel)
	statsBox.Add(recvCountLabel)

	copyPKBtn := widget.NewButtonWithIcon("Copy Public Key", theme.ContentCopyIcon(), func() {
		if selectedContact != nil {
			pkHex := hex.EncodeToString(selectedContact.PublicKey[:])
			app.Window.Clipboard().SetContent(pkHex)
		}
	})

	removeBtn := widget.NewButtonWithIcon("Remove Contact", theme.DeleteIcon(), func() {
		if selectedContact != nil {
			app.Contacts.Remove(selectedContact.FingerprintHex())
			app.Contacts.Save(data.DataDir())
			selectedContact = nil
			detailArea.Hide()
			if app.OnChatRefresh != nil {
				app.OnChatRefresh()
			}
		}
	})

	detailArea = container.NewVBox(
		widget.NewSeparator(),
		detailName,
		detailFP,
		widget.NewSeparator(),
		fpLabel, fpValue,
		pkLabel, detailPubKey,
		widget.NewSeparator(),
		container.NewHBox(copyPKBtn, layout.NewSpacer(), removeBtn),
		statsBox,
	)
	detailArea.Hide()

	noSelection := container.NewCenter(
		container.NewVBox(
			widget.NewLabelWithStyle("Select a contact", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
		),
	)

	updateDetail := func(c *identity.Contact) {
		if c == nil {
			detailArea.Hide()
			noSelection.Show()
			return
		}
		selectedContact = c
		detailName.SetText(c.DisplayName)
		detailFP.Text = c.FingerprintHex()
		detailFP.Refresh()
		fpValue.SetText(c.FingerprintHex())
		detailPubKey.SetText(hex.EncodeToString(c.PublicKey[:]))

		msgs := app.Data.GetMessages(c.FingerprintHex())
		total := len(msgs)
		sent := 0
		recv := 0
		for _, m := range msgs {
			if m.Direction == data.DirSent {
				sent++
			} else {
				recv++
			}
		}
		msgCountLabel.SetText("Messages: " + itoa(total))
		sentCountLabel.SetText("Sent: " + itoa(sent))
		recvCountLabel.SetText("Received: " + itoa(recv))

		noSelection.Hide()
		detailArea.Show()
	}

	// Contact list
	contacts := app.Contacts.List()
	contactList := widget.NewList(
		func() int {
			contacts = app.Contacts.List()
			return len(contacts)
		},
		func() fyne.CanvasObject {
			name := widget.NewLabelWithStyle("Name", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
			fp := canvas.NewText("fingerprint", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
			fp.TextSize = 11
			return container.NewVBox(name, fp)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			contacts = app.Contacts.List()
			if id >= len(contacts) {
				return
			}
			c := contacts[id]
			vbox := obj.(*fyne.Container)
			name := vbox.Objects[0].(*widget.Label)
			fp := vbox.Objects[1].(*canvas.Text)
			name.SetText(c.DisplayName)
			fp.Text = c.FingerprintHex()
			fp.Refresh()
		},
	)

	contactList.OnSelected = func(id widget.ListItemID) {
		contacts = app.Contacts.List()
		if id >= len(contacts) {
			return
		}
		updateDetail(contacts[id])
	}

	// Add contact button
	addBtn := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		showAddContactDialog(app, func() {
			contactList.Refresh()
			if app.OnChatRefresh != nil {
				app.OnChatRefresh()
			}
		})
	})

	listHeader := container.NewBorder(nil, nil,
		widget.NewLabelWithStyle("Contacts", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		addBtn,
	)

	leftPanel := container.NewBorder(
		container.NewVBox(listHeader, widget.NewSeparator()),
		nil, nil, nil,
		contactList,
	)

	rightPanel := container.NewStack(noSelection, container.NewScroll(detailArea))

	split := container.NewHSplit(leftPanel, rightPanel)
	split.SetOffset(0.35)
	return split
}

func showAddContactDialog(app *AppContext, onDone func()) {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Contact name")

	pkEntry := widget.NewMultiLineEntry()
	pkEntry.SetPlaceHolder("Public key (64 hex characters)")
	pkEntry.Wrapping = fyne.TextWrapBreak

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true})
	errorLabel.Importance = widget.DangerImportance

	content := container.NewVBox(
		widget.NewLabelWithStyle("Add Contact", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Name:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		nameEntry,
		widget.NewLabelWithStyle("Public Key (hex):", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		pkEntry,
		errorLabel,
	)

	d := dialog.NewCustomConfirm("Add Contact", "Add", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		name := nameEntry.Text
		pk := pkEntry.Text
		if name == "" {
			errorLabel.SetText("Name cannot be empty")
			return
		}

		contact, err := identity.NewContact(name, pk)
		if err != nil {
			errorLabel.SetText("Invalid public key. Must be 64 hex characters.")
			return
		}

		app.Contacts.Add(contact)
		app.Contacts.Save(data.DataDir())
		onDone()
	}, app.Window)
	d.Resize(fyne.NewSize(450, 350))
	d.Show()
}

func itoa(n int) string {
	return fmtInt(n)
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
