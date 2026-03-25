package ui

import (
	"encoding/hex"
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"freeflow-windows/client"
	"freeflow-windows/data"
	"freeflow-windows/identity"
)

// SettingsTab creates the settings tab (combined Identity + Settings).
func SettingsTab(app *AppContext) fyne.CanvasObject {
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Identity", theme.AccountIcon(), identityPanel(app)),
		container.NewTabItemWithIcon("Oracle", theme.ComputerIcon(), oraclePanel(app)),
		container.NewTabItemWithIcon("Transport", theme.MailSendIcon(), transportPanel(app)),
		container.NewTabItemWithIcon("Security", theme.WarningIcon(), securityPanel(app)),
		container.NewTabItemWithIcon("Advanced", theme.SettingsIcon(), advancedPanel(app)),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	return tabs
}

func identityPanel(app *AppContext) fyne.CanvasObject {
	if app.Identity == nil {
		// Create identity form
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("Your name")

		createBtn := widget.NewButtonWithIcon("Generate Identity", theme.ContentAddIcon(), func() {
			name := nameEntry.Text
			if name == "" {
				name = "Anonymous"
			}
			id, err := identity.NewIdentity(name)
			if err != nil {
				app.AddLog("error", fmt.Sprintf("Identity generation failed: %v", err))
				return
			}
			app.Identity = id
			identity.SaveIdentity(id, data.DataDir())
			app.Conn.Identity = id
			app.AddLog("success", fmt.Sprintf("Identity created: %s (fingerprint: %s)", name, id.FingerprintHex()))
			// Force refresh of the settings tab
			if app.OnSettingsRefresh != nil {
				app.OnSettingsRefresh()
			}
		})
		createBtn.Importance = widget.HighImportance

		return container.NewCenter(container.NewVBox(
			layout.NewSpacer(),
			widget.NewLabelWithStyle("Create Your Identity", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true}),
			widget.NewSeparator(),
			widget.NewLabelWithStyle("Generate an X25519 key pair for encrypted messaging.", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
			widget.NewLabelWithStyle("Your private key stays on this device.", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
			widget.NewSeparator(),
			nameEntry,
			createBtn,
			layout.NewSpacer(),
		))
	}

	id := app.Identity
	fpLabel := widget.NewLabelWithStyle("Fingerprint:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	fpValue := widget.NewEntry()
	fpValue.SetText(id.FingerprintHex())
	fpValue.Disable()

	pkLabel := widget.NewLabelWithStyle("Public Key:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	pkValue := widget.NewMultiLineEntry()
	pkValue.SetText(hex.EncodeToString(id.PublicKey[:]))
	pkValue.Disable()
	pkValue.Wrapping = fyne.TextWrapBreak
	pkValue.SetMinRowsVisible(2)

	copyBtn := widget.NewButtonWithIcon("Copy Public Key", theme.ContentCopyIcon(), func() {
		pk := hex.EncodeToString(id.PublicKey[:])
		app.Window.Clipboard().SetContent(pk)
	})

	nameLabel := widget.NewLabelWithStyle(id.DisplayName, fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})

	// Crypto details
	cryptoInfo := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Cryptographic Details", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		makeSettingsRow("Key Type", "X25519 (Curve25519)"),
		makeSettingsRow("Key Size", "256 bits"),
		makeSettingsRow("Fingerprint", "SHA-256(pubkey)[0:8]"),
		makeSettingsRow("E2E Cipher", "ChaCha20-Poly1305"),
		makeSettingsRow("Key Exchange", "ECDH + HKDF-SHA256"),
		makeSettingsRow("Signatures", "Ed25519"),
	)

	// Storage info
	storageInfo := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Storage", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		makeSettingsRow("Data Directory", data.DataDir()),
		makeSettingsRow("Identity File", "identity.json"),
		makeSettingsRow("Contacts File", "contacts.json"),
		makeSettingsRow("Messages File", "appdata.json"),
	)

	content := container.NewVBox(
		widget.NewLabelWithStyle("Your Identity", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		nameLabel,
		fpLabel, fpValue,
		pkLabel, pkValue,
		container.NewHBox(copyBtn, layout.NewSpacer()),
		cryptoInfo,
		storageInfo,
	)

	return container.NewScroll(container.NewPadded(content))
}

func oraclePanel(app *AppContext) fyne.CanvasObject {
	domainEntry := widget.NewEntry()
	domainEntry.SetText(app.Data.Settings.OracleDomain)
	domainEntry.OnChanged = func(s string) {
		app.Data.Settings.OracleDomain = s
		app.Conn.Domain = s
	}

	pubkeyEntry := widget.NewMultiLineEntry()
	pubkeyEntry.SetText(app.Data.Settings.OraclePubKeyHex)
	pubkeyEntry.Wrapping = fyne.TextWrapBreak
	pubkeyEntry.SetMinRowsVisible(2)
	pubkeyEntry.OnChanged = func(s string) {
		app.Data.Settings.OraclePubKeyHex = s
		// Parse and set oracle public key
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			var pk [32]byte
			copy(pk[:], b)
			app.Conn.OraclePublicKey = pk
		}
	}

	seedEntry := widget.NewMultiLineEntry()
	seedEntry.SetText(app.Data.Settings.BootstrapSeed)
	seedEntry.Wrapping = fyne.TextWrapBreak
	seedEntry.SetMinRowsVisible(2)
	seedEntry.OnChanged = func(s string) {
		app.Data.Settings.BootstrapSeed = s
	}

	saveBtn := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		app.Data.Save()
		app.AddLog("info", "Oracle settings saved")
	})

	content := container.NewVBox(
		widget.NewLabelWithStyle("Oracle Configuration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Domain:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		domainEntry,
		widget.NewLabelWithStyle("Oracle Public Key (hex):", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		pubkeyEntry,
		widget.NewLabelWithStyle("Bootstrap Seed (hex):", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		seedEntry,
		container.NewHBox(layout.NewSpacer(), saveBtn),
	)

	return container.NewScroll(container.NewPadded(content))
}

func transportPanel(app *AppContext) fyne.CanvasObject {
	// Encoding picker
	encodingSelect := widget.NewSelect(
		[]string{"Proquint (censored networks)", "Hex (uncensored)", "Lexical (legacy)"},
		func(s string) {
			switch s {
			case "Proquint (censored networks)":
				app.Conn.Encoding = client.EncodingProquint
				app.Data.Settings.QueryEncoding = "proquint"
			case "Hex (uncensored)":
				app.Conn.Encoding = client.EncodingHex
				app.Data.Settings.QueryEncoding = "hex"
			case "Lexical (legacy)":
				app.Conn.Encoding = client.EncodingLexical
				app.Data.Settings.QueryEncoding = "lexical"
			}
		},
	)
	switch app.Data.Settings.QueryEncoding {
	case "hex":
		encodingSelect.SetSelected("Hex (uncensored)")
	case "lexical":
		encodingSelect.SetSelected("Lexical (legacy)")
	default:
		encodingSelect.SetSelected("Proquint (censored networks)")
	}

	// Resolver
	resolverEntry := widget.NewEntry()
	resolverEntry.SetText(app.Data.Settings.Resolver)
	resolverEntry.OnChanged = func(s string) {
		app.Conn.Resolver = s
		app.Data.Settings.Resolver = s
	}

	// HTTP Relay toggle
	relayCheck := widget.NewCheck("Use HTTP Relay", func(b bool) {
		app.Conn.UseRelay = b
		app.Data.Settings.UseRelay = b
	})
	relayCheck.Checked = app.Data.Settings.UseRelay

	relayURLEntry := widget.NewEntry()
	relayURLEntry.SetText(app.Data.Settings.RelayURL)
	relayURLEntry.SetPlaceHolder("https://relay.example.com")
	relayURLEntry.OnChanged = func(s string) {
		app.Conn.RelayURL = s
		app.Data.Settings.RelayURL = s
	}

	relayKeyEntry := widget.NewEntry()
	relayKeyEntry.SetText(app.Data.Settings.RelayAPIKey)
	relayKeyEntry.SetPlaceHolder("API Key (optional)")
	relayKeyEntry.OnChanged = func(s string) {
		app.Conn.RelayAPIKey = s
		app.Data.Settings.RelayAPIKey = s
	}

	insecureCheck := widget.NewCheck("Allow insecure HTTP (no TLS)", func(b bool) {
		app.Conn.RelayInsecure = b
		app.Data.Settings.RelayInsecure = b
	})
	insecureCheck.Checked = app.Data.Settings.RelayInsecure

	insecureWarn := canvas.NewText("WARNING: Traffic will not be encrypted in transit.", color.NRGBA{R: 255, G: 0, B: 0, A: 255})
	insecureWarn.TextSize = 11
	insecureWarn.TextStyle = fyne.TextStyle{Monospace: true}

	saveBtn := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		app.Data.Save()
		app.AddLog("info", "Transport settings saved")
	})

	content := container.NewVBox(
		widget.NewLabelWithStyle("Transport Configuration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("DNS Resolver:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		resolverEntry,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("DNS Encoding:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		encodingSelect,
		widget.NewSeparator(),
		relayCheck,
		widget.NewLabelWithStyle("Relay URL:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		relayURLEntry,
		widget.NewLabelWithStyle("Relay API Key:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		relayKeyEntry,
		insecureCheck,
		insecureWarn,
		widget.NewSeparator(),
		container.NewHBox(layout.NewSpacer(), saveBtn),
	)

	return container.NewScroll(container.NewPadded(content))
}

func securityPanel(app *AppContext) fyne.CanvasObject {
	content := container.NewVBox(
		widget.NewLabelWithStyle("Encryption", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		makeSettingsRow("Key Agreement", "X25519 ECDH"),
		makeSettingsRow("Symmetric Cipher", "ChaCha20-Poly1305"),
		makeSettingsRow("Key Derivation", "HKDF-SHA256"),
		makeSettingsRow("Signatures", "Ed25519"),
		makeSettingsRow("Session Tokens", "HMAC-SHA256 rotating"),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Privacy", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		makeSettingsRow("Steganography", "Lexical (natural domain names)"),
		makeSettingsRow("DNS Transport", "AAAA records (IPv6)"),
		makeSettingsRow("CDN Masquerade", "Cloudflare/Google/AWS prefixes"),
		makeSettingsRow("Token Linkability", "None (per-query rotation)"),
	)

	if app.Identity != nil {
		content.Add(widget.NewSeparator())
		content.Add(widget.NewLabelWithStyle("Your Keys", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}))
		content.Add(widget.NewSeparator())
		content.Add(makeSettingsRow("Fingerprint", app.Identity.FingerprintHex()))

		pkEntry := widget.NewMultiLineEntry()
		pkEntry.SetText(hex.EncodeToString(app.Identity.PublicKey[:]))
		pkEntry.Disable()
		pkEntry.Wrapping = fyne.TextWrapBreak
		pkEntry.SetMinRowsVisible(2)
		content.Add(widget.NewLabelWithStyle("Public Key:", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}))
		content.Add(pkEntry)
	}

	return container.NewScroll(container.NewPadded(content))
}

func advancedPanel(app *AppContext) fyne.CanvasObject {
	// Query delay
	delayEntry := widget.NewEntry()
	delayEntry.SetText(fmt.Sprintf("%.1f", app.Data.Settings.QueryDelay))
	delayEntry.OnChanged = func(s string) {
		var d float64
		fmt.Sscanf(s, "%f", &d)
		if d > 0 {
			app.Data.Settings.QueryDelay = d
		}
	}

	// Dev mode
	devCheck := widget.NewCheck("Dev Mode (log all queries)", func(b bool) {
		app.Conn.DevMode = b
		app.Data.Settings.DevMode = b
	})
	devCheck.Checked = app.Data.Settings.DevMode

	devNote := canvas.NewText("Every DNS query and response will be logged in Connection > Dev Query Log tab.", color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	devNote.TextSize = 11
	devNote.TextStyle = fyne.TextStyle{Monospace: true}

	saveBtn := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		app.Data.Save()
		app.AddLog("info", "Settings saved")
	})

	content := container.NewVBox(
		widget.NewLabelWithStyle("Rate Limiting", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, widget.NewLabel("Query interval (sec):"), nil, delayEntry),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Developer", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		devCheck,
		devNote,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("About", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		makeSettingsRow("Version", "1.0.0"),
		makeSettingsRow("Protocol", "FreeFlow v2.1"),
		makeSettingsRow("Platform", "Windows (Go + Fyne)"),
		widget.NewSeparator(),
		container.NewHBox(layout.NewSpacer(), saveBtn),
	)

	return container.NewScroll(container.NewPadded(content))
}

func makeSettingsRow(label, value string) fyne.CanvasObject {
	l := canvas.NewText(label, color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	l.TextSize = 13
	l.TextStyle = fyne.TextStyle{Monospace: true}
	v := canvas.NewText(value, color.NRGBA{R: 0, G: 200, B: 0, A: 255})
	v.TextSize = 13
	v.TextStyle = fyne.TextStyle{Monospace: true}
	return container.NewHBox(l, layout.NewSpacer(), v)
}
