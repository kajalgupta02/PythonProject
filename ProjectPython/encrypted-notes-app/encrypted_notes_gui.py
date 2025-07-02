import tkinter as tk
from tkinter import messagebox
import os
import string

# ========== Encryption Logic ==========
def encrypt(text, key):
    return ''.join(
        string.printable[(string.printable.index(c) + key) % len(string.printable)]
        if c in string.printable else c for c in text
    )

def decrypt(text, key):
    return ''.join(
        string.printable[(string.printable.index(c) - key) % len(string.printable)]
        if c in string.printable else c for c in text
    )

# ========== File Functions ==========
NOTES_DIR = "notes"
LAST_NOTE_FILE = "last_opened.txt"

def ensure_notes_dir():
    if not os.path.exists(NOTES_DIR):
        os.makedirs(NOTES_DIR)

def get_note_titles():
    ensure_notes_dir()
    return sorted([f for f in os.listdir(NOTES_DIR) if f.endswith(".txt")])

def save_note_to_file(filename, content):
    with open(os.path.join(NOTES_DIR, filename), "w") as f:
        f.write(content)

def read_note_from_file(filename):
    with open(os.path.join(NOTES_DIR, filename), "r") as f:
        return f.read()

def delete_note_file(filename):
    os.remove(os.path.join(NOTES_DIR, filename))

def save_last_opened(note):
    with open(LAST_NOTE_FILE, "w") as f:
        f.write(note)

def load_last_opened():
    if os.path.exists(LAST_NOTE_FILE):
        with open(LAST_NOTE_FILE, "r") as f:
            return f.read().strip()
    return None

# ========== GUI Logic ==========
def refresh_notes():
    note_listbox.delete(0, tk.END)
    for note in get_note_titles():
        note_listbox.insert(tk.END, note)
    update_status("Notes refreshed ✅")

    last_note = load_last_opened()
    if last_note and last_note in get_note_titles():
        note_var.set(last_note)
        idx = get_note_titles().index(last_note)
        note_listbox.selection_set(idx)
        note_listbox.activate(idx)

def on_note_select(event):
    selection = note_listbox.curselection()
    if selection:
        selected = note_listbox.get(selection[0])
        note_var.set(selected)
        if password_entry.get().isdigit():
            try:
                encrypted = read_note_from_file(selected)
                decrypted = decrypt(encrypted, int(password_entry.get()))
                text_area.delete("1.0", tk.END)
                text_area.insert(tk.END, decrypted)
                title_entry.delete(0, tk.END)
                title_entry.insert(0, selected.replace(".txt", ""))
                update_status(f"Note '{selected}' auto-decrypted 🔓")
                save_last_opened(selected)
            except Exception as e:
                update_status("Auto-decrypt failed ❌")
        else:
            update_status("Note selected. Enter password to decrypt 🔑")

def update_status(msg):
    status_var.set(msg)

def save_note():
    title = title_entry.get().strip()
    password = password_entry.get()
    note = text_area.get("1.0", tk.END).strip()

    if not title or not password.isdigit() or not note:
        messagebox.showerror("Error", "Please enter a valid title, numeric password, and note.")
        return

    encrypted = encrypt(note, int(password))
    save_note_to_file(title + ".txt", encrypted)
    refresh_notes()
    update_status(f"Note '{title}' saved 💾")

def decrypt_note():
    filename = note_var.get()
    password = password_entry.get()

    if not filename or not password.isdigit():
        messagebox.showerror("Error", "Select a note and enter numeric password.")
        return

    try:
        encrypted = read_note_from_file(filename)
        decrypted = decrypt(encrypted, int(password))
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, decrypted)
        title_entry.delete(0, tk.END)
        title_entry.insert(0, filename.replace(".txt", ""))
        update_status(f"Note '{filename}' decrypted 🔓")
        save_last_opened(filename)
    except Exception as e:
        messagebox.showerror("Error", "Failed to decrypt. Incorrect password?")
        update_status("Decryption failed ❌")

def clear_all():
    text_area.delete("1.0", tk.END)
    title_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    note_var.set("")
    note_listbox.selection_clear(0, tk.END)
    update_status("Cleared all fields 🧹")

def delete_note():
    filename = note_var.get()
    if not filename:
        messagebox.showwarning("Warning", "Select a note to delete.")
        return
    if messagebox.askyesno("Confirm Delete", f"Delete '{filename}'?"):
        delete_note_file(filename)
        refresh_notes()
        clear_all()
        update_status(f"'{filename}' deleted 🗑")

def filter_notes(*args):
    keyword = search_var.get().lower()
    note_listbox.delete(0, tk.END)
    for note in get_note_titles():
        if keyword in note.lower():
            note_listbox.insert(tk.END, note)

# ========== Start GUI Window ========== 
root = tk.Tk()
root.title("🔐 Encrypted Notes – Enhanced GUI")
root.geometry("1024x720")
root.configure(bg="#2c3e50")

font_label = ("Segoe UI", 10)
font_entry = ("Segoe UI", 11)
font_text = ("Consolas", 12)

sidebar = tk.Frame(root, bg="#34495e", width=180, relief="sunken", bd=0)
sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

note_var = tk.StringVar()
search_var = tk.StringVar()
search_var.trace("w", filter_notes)

status_var = tk.StringVar()

main_frame = tk.Frame(root, bg="#ecf0f1")
main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# ====== Sidebar ======
tk.Label(sidebar, text="📋 Notes", font=("Segoe UI", 11, "bold"), bg="#34495e", fg="white").pack(pady=5)
search_entry = tk.Entry(sidebar, textvariable=search_var, width=25)
search_entry.pack(pady=(0, 5))
search_entry.insert(0, "Search notes...")
search_entry.bind("<FocusIn>", lambda e: search_entry.delete(0, tk.END) if search_entry.get() == "Search notes..." else None)

note_listbox = tk.Listbox(sidebar, height=25, width=25, bg="white", fg="black")
note_listbox.pack(padx=5)
note_listbox.bind("<<ListboxSelect>>", on_note_select)

btn_refresh = tk.Button(sidebar, text="🔄 Refresh", command=refresh_notes, bg="#3498db", fg="white")
btn_refresh.pack(pady=3)
btn_delete = tk.Button(sidebar, text="🗑 Delete", command=delete_note, bg="#e74c3c", fg="white")
btn_delete.pack(pady=3)

# ====== Text Area ======
tk.Label(main_frame, text="📝 Note:", font=("Segoe UI", 11, "bold"), bg="#ecf0f1").pack(anchor="w")
text_area = tk.Text(main_frame, height=30, width=120, font=font_text, wrap=tk.WORD, bg="white", relief="flat", bd=2)
text_area.pack(pady=5)

form_frame = tk.Frame(main_frame, bg="#ecf0f1")
form_frame.pack(pady=5)

# ====== Form Inputs and Buttons ======
tk.Label(form_frame, text="Title:", bg="#ecf0f1").grid(row=0, column=0, padx=5)
title_entry = tk.Entry(form_frame, font=font_entry, width=20)
title_entry.grid(row=0, column=1, padx=5)

tk.Label(form_frame, text="Password:", bg="#ecf0f1").grid(row=0, column=2, padx=5)
password_entry = tk.Entry(form_frame, show="*", font=font_entry, width=10)
password_entry.grid(row=0, column=3, padx=5)

tk.Button(form_frame, text="💾 Save", command=save_note, bg="#27ae60", fg="white", width=10).grid(row=0, column=4, padx=5)
tk.Button(form_frame, text="🔓 Decrypt", command=decrypt_note, bg="#2980b9", fg="white", width=10).grid(row=0, column=5, padx=5)
tk.Button(form_frame, text="🧹 Clear", command=clear_all, bg="#95a5a6", fg="white", width=10).grid(row=0, column=6, padx=5)

# ====== Status Bar ======
status_label = tk.Label(root, textvariable=status_var, bg="#2c3e50", fg="white", anchor="w", font=("Segoe UI", 9))
status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=2, padx=5)

# ====== Init ======
ensure_notes_dir()
refresh_notes()
update_status("Ready ✅")

root.mainloop()