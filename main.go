package main

import (
	"encoding/hex"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"

	"freeflow-windows/client"
	"freeflow-windows/data"
	"freeflow-windows/identity"
	"freeflow-windows/ui"
)

func main() {
	a := app.NewWithID("io.freeflow.windows")
	a.Settings().SetTheme(&ui.UnicodeTheme{})

	w := a.NewWindow("FreeFlow")
	w.Resize(fyne.NewSize(1100, 750))

	// Load persisted data
	appData := data.NewAppData()
	appData.Load()

	// Load or create identity
	dir := data.DataDir()
	id, err := identity.LoadIdentity(dir)
	if err != nil {
		// No identity yet, will be created from Settings tab
		id = nil
	}

	// Load contacts
	contacts := identity.NewContactStore()
	contacts.Load(dir)

	// Parse Oracle public key from settings
	var oraclePubKey [32]byte
	if pk, err := hex.DecodeString(appData.Settings.OraclePubKeyHex); err == nil && len(pk) == 32 {
		copy(oraclePubKey[:], pk)
	}

	// Create connection
	conn := client.NewConnection(id, oraclePubKey)
	conn.Domain = appData.Settings.OracleDomain
	conn.Resolver = appData.Settings.Resolver
	conn.DevMode = appData.Settings.DevMode
	conn.UseRelay = appData.Settings.UseRelay
	conn.RelayURL = appData.Settings.RelayURL
	conn.RelayAPIKey = appData.Settings.RelayAPIKey
	conn.RelayInsecure = appData.Settings.RelayInsecure
	conn.SkipAutoTune = appData.Settings.SkipAutoTune
	conn.ManualDelay = appData.Settings.ManualDelay

	switch appData.Settings.QueryEncoding {
	case "hex":
		conn.Encoding = client.EncodingHex
	case "lexical":
		conn.Encoding = client.EncodingLexical
	default:
		conn.Encoding = client.EncodingProquint
	}

	if appData.Settings.QueryDelay > 0 {
		conn.QueryDelay = time.Duration(appData.Settings.QueryDelay * float64(time.Second))
	}

	// Build app context
	appCtx := &ui.AppContext{
		Window:   w,
		Identity: id,
		Contacts: contacts,
		Conn:     conn,
		Data:     appData,
	}

	// Build tabs
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Chats", theme.MailComposeIcon(), ui.ChatsTab(appCtx)),
		container.NewTabItemWithIcon("Contacts", theme.AccountIcon(), ui.ContactsTab(appCtx)),
		container.NewTabItemWithIcon("Bulletins", theme.InfoIcon(), ui.BulletinsTab(appCtx)),
		container.NewTabItemWithIcon("Connection", theme.ComputerIcon(), ui.ConnectionTab(appCtx)),
		container.NewTabItemWithIcon("Settings", theme.SettingsIcon(), ui.SettingsTab(appCtx)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	// If no identity, start on Settings tab
	if id == nil {
		tabs.SelectIndex(4)
	}

	w.SetContent(tabs)

	// Save on close
	w.SetOnClosed(func() {
		appData.Save()
		contacts.Save(dir)
	})

	w.ShowAndRun()
}
