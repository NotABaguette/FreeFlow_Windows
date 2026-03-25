package ui

import (
	"fyne.io/fyne/v2"

	"freeflow-windows/client"
	"freeflow-windows/data"
	"freeflow-windows/identity"
)

// AppContext holds all shared state for the UI.
type AppContext struct {
	Window   fyne.Window
	Identity *identity.Identity
	Contacts *identity.ContactStore
	Conn     *client.Connection
	Data     *data.AppData

	// Callbacks for cross-tab refresh
	OnChatRefresh     func()
	OnSettingsRefresh func()
}

// AddLog adds a log entry to the connection log.
func (ctx *AppContext) AddLog(level, msg string) {
	ctx.Conn.Log = append(ctx.Conn.Log, client.LogEntry{
		Level:   level,
		Message: msg,
	})
	if ctx.Conn.OnLog != nil {
		ctx.Conn.OnLog(client.LogEntry{
			Level:   level,
			Message: msg,
		})
	}
}
