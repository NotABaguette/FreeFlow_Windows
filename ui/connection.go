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

	"freeflow-windows/client"
)

// ConnectionTab creates the connection management tab.
func ConnectionTab(app *AppContext) fyne.CanvasObject {
	// Status indicators
	statusDot := canvas.NewCircle(color.NRGBA{R: 255, G: 0, B: 0, A: 255})
	statusDot.Resize(fyne.NewSize(12, 12))
	statusLabel := widget.NewLabelWithStyle("Disconnected", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
	transportLabel := canvas.NewText("DNS Transport", color.NRGBA{R: 0, G: 200, B: 200, A: 255})
	transportLabel.TextSize = 12
	transportLabel.TextStyle = fyne.TextStyle{Monospace: true}

	queryCountLabel := widget.NewLabelWithStyle("Queries: 0", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	latencyLabel := widget.NewLabelWithStyle("Latency: --", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	sessionLabel := widget.NewLabelWithStyle("Session: None", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	serverTimeLabel := widget.NewLabelWithStyle("Server Time: --", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})

	// Connection log
	logText := widget.NewMultiLineEntry()
	logText.Disable()
	logText.Wrapping = fyne.TextWrapWord
	logText.SetMinRowsVisible(12)

	// Dev query log
	devLogText := widget.NewMultiLineEntry()
	devLogText.Disable()
	devLogText.Wrapping = fyne.TextWrapWord
	devLogText.SetMinRowsVisible(12)

	updateStatus := func() {
		switch app.Conn.State {
		case client.StateConnected:
			statusDot.FillColor = color.NRGBA{R: 0, G: 200, B: 0, A: 255}
			statusLabel.SetText("Connected")
		case client.StateConnecting:
			statusDot.FillColor = color.NRGBA{R: 255, G: 200, B: 0, A: 255}
			statusLabel.SetText("Connecting...")
		default:
			statusDot.FillColor = color.NRGBA{R: 255, G: 0, B: 0, A: 255}
			statusLabel.SetText("Disconnected")
		}
		statusDot.Refresh()
		statusLabel.Refresh()

		if app.Conn.UseRelay {
			transportLabel.Text = "HTTP Relay"
			transportLabel.Color = color.NRGBA{R: 255, G: 165, B: 0, A: 255}
		} else {
			transportLabel.Text = fmt.Sprintf("DNS(%s)", app.Conn.Encoding)
			transportLabel.Color = color.NRGBA{R: 0, G: 200, B: 200, A: 255}
		}
		transportLabel.Refresh()

		queryCountLabel.SetText(fmt.Sprintf("Queries: %d", app.Conn.QueryCount))
		if app.Conn.PingLatency > 0 {
			latencyLabel.SetText(fmt.Sprintf("Latency: %dms", app.Conn.PingLatency.Milliseconds()))
		}
		if app.Conn.Session != nil {
			sessionLabel.SetText("Session: Active")
		} else {
			sessionLabel.SetText("Session: None")
		}
		if !app.Conn.ServerTime.IsZero() {
			serverTimeLabel.SetText("Server Time: " + app.Conn.ServerTime.Format("15:04:05"))
		}
	}

	appendLog := func(entry client.LogEntry) {
		prefix := ""
		switch entry.Level {
		case "info":
			prefix = "[i] "
		case "success":
			prefix = "[+] "
		case "warn":
			prefix = "[!] "
		case "error":
			prefix = "[x] "
		}
		line := entry.Time.Format("15:04:05") + " " + prefix + entry.Message + "\n"
		logText.SetText(logText.Text + line)
		logText.CursorRow = len(logText.Text)
	}

	appendDevLog := func(entry client.QueryLogEntry) {
		line := fmt.Sprintf("%s [%s] Q: %s | R: %s\n",
			entry.Time.Format("15:04:05"), entry.Transport, entry.Query, entry.Response)
		devLogText.SetText(devLogText.Text + line)
	}

	// Set callbacks
	app.Conn.OnLog = func(entry client.LogEntry) {
		appendLog(entry)
		updateStatus()
	}
	app.Conn.OnQueryLog = func(entry client.QueryLogEntry) {
		appendDevLog(entry)
	}
	app.Conn.OnStateChange = func(s client.ConnectionState) {
		updateStatus()
	}

	// Action buttons
	connectBtn := widget.NewButtonWithIcon("Connect", theme.MediaPlayIcon(), nil)
	connectBtn.Importance = widget.HighImportance

	connectBtn.OnTapped = func() {
		if app.Conn.State == client.StateConnected {
			app.Conn.Disconnect()
			connectBtn.SetText("Connect")
			connectBtn.Importance = widget.HighImportance
			updateStatus()
		} else {
			connectBtn.SetText("Connecting...")
			connectBtn.Disable()
			go func() {
				err := app.Conn.Connect()
				if err != nil {
					app.AddLog("error", fmt.Sprintf("Connect failed: %v", err))
				}
				connectBtn.Enable()
				if app.Conn.State == client.StateConnected {
					connectBtn.SetText("Disconnect")
					connectBtn.Importance = widget.DangerImportance
				} else {
					connectBtn.SetText("Connect")
					connectBtn.Importance = widget.HighImportance
				}
				updateStatus()
			}()
		}
	}

	pingBtn := widget.NewButtonWithIcon("Ping", theme.InfoIcon(), func() {
		go func() {
			_, err := app.Conn.Ping()
			if err != nil {
				app.AddLog("error", fmt.Sprintf("Ping failed: %v", err))
			}
			updateStatus()
		}()
	})

	cacheTestBtn := widget.NewButtonWithIcon("Cache Test", theme.StorageIcon(), func() {
		go func() {
			ttl, ok, err := app.Conn.CacheTest()
			if err != nil {
				app.AddLog("error", fmt.Sprintf("Cache test failed: %v", err))
			} else {
				app.AddLog("info", fmt.Sprintf("Cache test: TTL=%d fresh=%v", ttl, ok))
			}
			updateStatus()
		}()
	})

	discoverBtn := widget.NewButtonWithIcon("Discover", theme.SearchIcon(), func() {
		go func() {
			_, err := app.Conn.Discover()
			if err != nil {
				app.AddLog("error", fmt.Sprintf("Discover failed: %v", err))
			}
			updateStatus()
		}()
	})

	actionRow := container.NewGridWithColumns(4, connectBtn, pingBtn, cacheTestBtn, discoverBtn)

	// Resolver and domain config
	resolverEntry := widget.NewEntry()
	resolverEntry.SetText(app.Conn.Resolver)
	resolverEntry.SetPlaceHolder("8.8.8.8")
	resolverEntry.OnChanged = func(s string) {
		app.Conn.Resolver = s
		app.Data.Settings.Resolver = s
	}

	domainEntry := widget.NewEntry()
	domainEntry.SetText(app.Conn.Domain)
	domainEntry.SetPlaceHolder("cdn-static-eu.net")
	domainEntry.OnChanged = func(s string) {
		app.Conn.Domain = s
		app.Data.Settings.OracleDomain = s
	}

	configRow := container.NewGridWithColumns(2,
		container.NewBorder(nil, nil, widget.NewLabel("Resolver:"), nil, resolverEntry),
		container.NewBorder(nil, nil, widget.NewLabel("Domain:"), nil, domainEntry),
	)

	// Skip auto-tune toggle
	skipAutoTuneCheck := widget.NewCheck("Skip auto-tune", func(b bool) {
		app.Conn.SkipAutoTune = b
		app.Data.Settings.SkipAutoTune = b
	})
	skipAutoTuneCheck.Checked = app.Conn.SkipAutoTune

	manualDelayEntry := widget.NewEntry()
	manualDelayEntry.SetText(fmt.Sprintf("%.1f", app.Conn.ManualDelay))
	manualDelayEntry.OnChanged = func(s string) {
		var d float64
		fmt.Sscanf(s, "%f", &d)
		if d > 0 {
			app.Conn.ManualDelay = d
			app.Conn.QueryDelay = time.Duration(d * float64(time.Second))
		}
	}

	autoTuneRow := container.NewHBox(
		skipAutoTuneCheck,
		widget.NewLabel("Delay:"),
		manualDelayEntry,
		widget.NewLabel("sec"),
	)

	// Session info box (shown when connected)
	sessionInfo := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Session Details", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		makeInfoRow("State", "Established"),
		makeInfoRow("Cipher", "ChaCha20-Poly1305"),
		makeInfoRow("Key Exchange", "X25519 ECDH"),
		makeInfoRow("Key Derivation", "HKDF-SHA256"),
		makeInfoRow("Token Rotation", "HMAC-SHA256 per query"),
	)

	// Log tabs
	logTabs := container.NewAppTabs(
		container.NewTabItem("Connection Log", logText),
		container.NewTabItem("Dev Query Log", devLogText),
	)

	statusRow := container.NewHBox(
		container.NewWithoutLayout(statusDot),
		statusLabel,
		layout.NewSpacer(),
		transportLabel,
	)
	// Manually position the status dot
	statusDot.Move(fyne.NewPos(0, 4))

	statsRow := container.NewGridWithColumns(4, queryCountLabel, latencyLabel, sessionLabel, serverTimeLabel)

	content := container.NewVBox(
		widget.NewLabelWithStyle("Connection", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		statusRow,
		statsRow,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Actions", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		actionRow,
		autoTuneRow,
		configRow,
		sessionInfo,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		logTabs,
	)

	return container.NewScroll(container.NewPadded(content))
}

func makeInfoRow(label, value string) fyne.CanvasObject {
	l := canvas.NewText(label, color.NRGBA{R: 128, G: 128, B: 128, A: 200})
	l.TextSize = 12
	l.TextStyle = fyne.TextStyle{Monospace: true}
	v := canvas.NewText(value, color.NRGBA{R: 0, G: 200, B: 0, A: 255})
	v.TextSize = 12
	v.TextStyle = fyne.TextStyle{Monospace: true}
	return container.NewHBox(container.NewWithoutLayout(l), layout.NewSpacer(), v)
}
