package ui

import (
	_ "embed"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

//go:embed NotoSans-Regular.ttf
var notoSansRegular []byte

// UnicodeTheme is a dark theme that uses Noto Sans for full Unicode
// support including Persian/Arabic, CJK, and other scripts.
type UnicodeTheme struct{}

var _ fyne.Theme = (*UnicodeTheme)(nil)

func (u *UnicodeTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return theme.DarkTheme().Color(name, variant)
}

func (u *UnicodeTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DarkTheme().Icon(name)
}

func (u *UnicodeTheme) Font(style fyne.TextStyle) fyne.Resource {
	return fyne.NewStaticResource("NotoSans-Regular.ttf", notoSansRegular)
}

func (u *UnicodeTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DarkTheme().Size(name)
}
