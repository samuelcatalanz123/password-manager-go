// Package ui contiene la ventana de escritorio (Fyne) de CajaFuerte.
package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelcatalanz123/password-manager-go/internal/vault"
)

// Run arranca la app de escritorio usando el archivo de caja en vaultPath.
func Run(vaultPath string) {
	a := app.New()
	w := a.NewWindow("CajaFuerte 🔐")
	w.Resize(fyne.NewSize(420, 480))
	showLogin(w, vaultPath)
	w.ShowAndRun()
}

// showLogin muestra la pantalla para crear o introducir la maestra.
func showLogin(w fyne.Window, path string) {
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("Contraseña maestra")
	info := widget.NewLabel("")

	first := !vault.Exists(path)
	title := "Introduce tu contraseña maestra"
	btnText := "Abrir"
	if first {
		title = "Crea tu contraseña maestra (no la olvides)"
		btnText = "Crear"
	}

	action := func() {
		if pass.Text == "" {
			info.SetText("Escribe una contraseña.")
			return
		}
		var v *vault.Vault
		var err error
		if first {
			v, err = vault.Create(path, pass.Text)
		} else {
			v, err = vault.Open(path, pass.Text)
		}
		if err != nil {
			info.SetText("Contraseña incorrecta.")
			return
		}
		showList(w, v)
	}
	pass.OnSubmitted = func(string) { action() }

	form := container.NewVBox(
		widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		pass,
		widget.NewButton(btnText, action),
		info,
	)
	w.SetContent(container.NewPadded(form))
}

// showList muestra las entradas con botones añadir/copiar/borrar.
func showList(w fyne.Window, v *vault.Vault) {
	list := widget.NewList(
		func() int { return len(v.Entries) },
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			e := v.Entries[i]
			o.(*widget.Label).SetText(e.Site + "  —  " + e.Username)
		},
	)

	selected := -1
	list.OnSelected = func(i widget.ListItemID) { selected = i }

	addBtn := widget.NewButton("➕ Añadir", func() {
		site := widget.NewEntry()
		user := widget.NewEntry()
		pw := widget.NewPasswordEntry()
		items := []*widget.FormItem{
			widget.NewFormItem("Sitio", site),
			widget.NewFormItem("Usuario", user),
			widget.NewFormItem("Contraseña", pw),
		}
		dialog.ShowForm("Nueva entrada", "Guardar", "Cancelar", items, func(ok bool) {
			if !ok || site.Text == "" {
				return
			}
			if err := v.Add(vault.Entry{Site: site.Text, Username: user.Text, Password: pw.Text}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			list.Refresh()
		}, w)
	})

	copyBtn := widget.NewButton("📋 Copiar contraseña", func() {
		if selected < 0 || selected >= len(v.Entries) {
			dialog.ShowInformation("Copiar", "Selecciona una entrada primero.", w)
			return
		}
		w.Clipboard().SetContent(v.Entries[selected].Password)
		dialog.ShowInformation("Copiado", "Contraseña copiada al portapapeles.", w)
	})

	delBtn := widget.NewButton("🗑️ Borrar", func() {
		if selected < 0 || selected >= len(v.Entries) {
			dialog.ShowInformation("Borrar", "Selecciona una entrada primero.", w)
			return
		}
		dialog.ShowConfirm("Borrar", "¿Borrar esta entrada?", func(ok bool) {
			if !ok {
				return
			}
			if err := v.Delete(selected); err != nil {
				dialog.ShowError(err, w)
				return
			}
			selected = -1
			list.UnselectAll()
			list.Refresh()
		}, w)
	})

	buttons := container.NewHBox(addBtn, copyBtn, delBtn)
	w.SetContent(container.NewBorder(
		widget.NewLabelWithStyle("Tus contraseñas", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		buttons, nil, nil, list,
	))
}
