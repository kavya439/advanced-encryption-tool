import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet
import os

key = Fernet.generate_key()
print("Key:", key)

fernet = Fernet(key)
data = b"Test data for encryption"

encrypted = fernet.encrypt(data)
print("Encrypted:", encrypted)

decrypted = fernet.decrypt(encrypted)
print("Decrypted:", decrypted)


class AdvancedEncryptionTool:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Encryption Tool")
        master.geometry("700x550")  # Increased window size for better layout
        master.resizable(False, False)
        master.config(bg="#f8f1e5")  # Light background

        # --- Styling ---
        self.font_large = ("Helvetica", 14, "bold")
        self.font_medium = ("Helvetica", 12)
        self.button_color = "#e67e22"  # Orange
        self.text_color = "#34495e"  # Dark blue-grey
        self.header_color = "#2c3e50"  # Even darker blue-grey

        # --- Header ---
        self.header_frame = tk.Frame(master, bg=self.header_color, pady=10)
        self.header_frame.pack(fill="x")
        self.header_label = tk.Label(
            self.header_frame,
            text="ADVANCED ENCRYPTION TOOL",
            fg="white",
            bg=self.header_color,
            font=("Helvetica", 18, "bold"),
        )
        self.header_label.pack(pady=5)

        # --- Key Management Section ---
        self.key_frame = tk.LabelFrame(
            master,
            text="Encryption Key Management",
            font=self.font_large,
            fg=self.text_color,
            bg="#f8f1e5",
            padx=15,
            pady=10,
        )
        self.key_frame.pack(pady=15, padx=20, fill="x")

        self.key_label = tk.Label(
            self.key_frame,
            text="Current Key:",
            font=self.font_medium,
            bg="#f8f1e5",
            fg=self.text_color,
        )
        self.key_display = scrolledtext.ScrolledText(self.key_frame, height=3, width=60, wrap=tk.WORD, font=("Consolas", 10), state="disabled", bg="#ecf0f1", fg=self.text_color)
        def display_current_key(self):
             self.key_display.config(state="normal")
             self.key_display.delete(1.0, tk.END)
             if self.key:
                  self.key_display.insert(tk.END, self.key.decode() + "\n\n\n\n\n")  # Add blank lines to enable scrollbar
             else:
                 self.key_display.insert(tk.END, "No key loaded. Generate or load a key to proceed.\n\n\n\n\n")
                 self.key_display.config(state="disabled")


        self.key_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        # Make sure the key_display spans correctly
        self.key_frame.grid_columnconfigure(1, weight=1)  # Allow key display to expand
        self.key_display = scrolledtext.ScrolledText(
            self.key_frame,
            height=2,
            width=60,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state="disabled",
            bg="#ecf0f1",
            fg=self.text_color,
        )
        self.key_display.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.generate_key_button = tk.Button(
            self.key_frame,
            text="Generate New Key",
            command=self.generate_key,
            font=self.font_medium,
            bg=self.button_color,
            fg="white",
            activebackground="#d35400",
            padx=10,
            pady=5,
        )
        self.generate_key_button.grid(row=1, column=0, padx=5, pady=10, sticky="w")

        self.load_key_button = tk.Button(
            self.key_frame,
            text="Load Key from File",
            command=self.load_key,
            font=self.font_medium,
            bg=self.button_color,
            fg="white",
            activebackground="#d35400",
            padx=10,
            pady=5,
        )
        self.load_key_button.grid(row=1, column=1, padx=5, pady=10, sticky="w")

        self.save_key_button = tk.Button(
            self.key_frame,
            text="Save Current Key",
            command=self.save_key,
            font=self.font_medium,
            bg=self.button_color,
            fg="white",
            activebackground="#d35400",
            padx=10,
            pady=5,
        )
        self.save_key_button.grid(row=1, column=1, padx=5, pady=10, sticky="e")

        # --- File Operations Section ---
        self.file_frame = tk.LabelFrame(
            master,
            text="File Operations",
            font=self.font_large,
            fg=self.text_color,
            bg="#f8f1e5",
            padx=15,
            pady=10,
        )
        self.file_frame.pack(pady=15, padx=20, fill="x")

        self.filepath_label = tk.Label(
            self.file_frame,
            text="Selected File:",
            font=self.font_medium,
            bg="#f8f1e5",
            fg=self.text_color,
        )
        self.filepath_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        # Allow filepath_entry to expand
        self.file_frame.grid_columnconfigure(1, weight=1)

        self.filepath_entry = tk.Entry(
            self.file_frame,
            width=50,
            font=self.font_medium,
            state="readonly",
            bg="#ecf0f1",
            fg=self.text_color,
        )
        self.filepath_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.browse_button = tk.Button(
            self.file_frame,
            text="Browse File",
            command=self.browse_file,
            font=self.font_medium,
            bg=self.button_color,
            fg="white",
            activebackground="#d35400",
            padx=10,
            pady=5,
        )
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)

        # Encrypt and Decrypt buttons full width below the file selector
        self.encrypt_button = tk.Button(
            self.file_frame,
            text="Encrypt File",
            command=self.encrypt_file,
            font=self.font_large,
            bg="#27ae60",  # Green
            fg="white",
            activebackground="#229954",
            padx=15,
            pady=10,
        )
        self.encrypt_button.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        self.decrypt_button = tk.Button(
            self.file_frame,
            text="Decrypt File",
            command=self.decrypt_file,
            font=self.font_large,
            bg="#e74c3c",  # Red
            fg="white",
            activebackground="#c0392b",
            padx=15,
            pady=10,
        )
        self.decrypt_button.grid(row=2, column=0, columnspan=3, padx=10, pady=(0, 10), sticky="ew")

        # --- Status Bar ---
        self.status_bar = tk.Label(
            master,
            text="Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            font=("Helvetica", 10),
            bg="#ecf0f1",
            fg=self.text_color,
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.key = None  # Initialize key to None
        self.display_current_key()  # Update key display on startup

    def display_current_key(self):
        """Updates the key display area."""
        self.key_display.config(state="normal")
        self.key_display.delete(1.0, tk.END)
        if self.key:
            self.key_display.insert(tk.END, self.key.decode())
        else:
            self.key_display.insert(tk.END, "No key loaded. Generate or load a key to proceed.")
        self.key_display.config(state="disabled")

    def generate_key(self):
        """Generates a new AES key and updates the display."""
        try:
            self.key = Fernet.generate_key()
            self.display_current_key()
            messagebox.showinfo("Key Generated", "A new encryption key has been generated.")
            self.update_status("New key generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {e}")
            self.update_status("Error generating key.")

    def load_key(self):
        """Loads an encryption key from a file."""
        file_path = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )
        if file_path:
            try:
                with open(file_path, "rb") as key_file:
                    self.key = key_file.read()
                self.display_current_key()
                messagebox.showinfo("Key Loaded", "Encryption key loaded successfully.")
                self.update_status(f"Key loaded from {os.path.basename(file_path)}.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {e}")
                self.key = None
                self.display_current_key()
                self.update_status("Error loading key.")

    def save_key(self):
        """Saves the current encryption key to a file."""
        if not self.key:
            messagebox.showwarning("No Key", "Please generate a key first before saving.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Key As",
            defaultextension=".key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )
        if file_path:
            try:
                with open(file_path, "wb") as key_file:
                    key_file.write(self.key)
                messagebox.showinfo("Key Saved", f"Key saved successfully to {file_path}")
                self.update_status(f"Key saved to {os.path.basename(file_path)}.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {e}")
                self.update_status("Error saving key.")

    def browse_file(self):
        """Allows user to select a file for encryption/decryption."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.filepath_entry.config(state="normal")
            self.filepath_entry.delete(0, tk.END)
            self.filepath_entry.insert(0, file_path)
            self.filepath_entry.config(state="readonly")
            self.update_status(f"File selected: {os.path.basename(file_path)}")
        else:
            self.filepath_entry.config(state="normal")
            self.filepath_entry.delete(0, tk.END)
            self.filepath_entry.config(state="readonly")
            self.update_status("No file selected.")

    def encrypt_file(self):
        """Encrypts the selected file using the loaded key."""
        if not self.key:
            messagebox.showwarning("No Key", "Please generate or load an encryption key first.")
            return

        file_path = self.filepath_entry.get()
        if not file_path:
            messagebox.showwarning("No File", "Please select a file to encrypt.")
            return

        try:
            fernet = Fernet(self.key)
            with open(file_path, "rb") as file:
                original_data = file.read()
            encrypted_data = fernet.encrypt(original_data)

            encrypted_file_path = file_path + ".encrypted"
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)

            messagebox.showinfo(
                "Encryption Successful",
                f"File encrypted successfully!\nSaved as: {os.path.basename(encrypted_file_path)}",
            )
            self.update_status(f"File encrypted: {os.path.basename(file_path)}.")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt file: {e}")
            self.update_status("Encryption failed.")

    def decrypt_file(self):
        """Decrypts the selected file using the loaded key."""
        if not self.key:
            messagebox.showwarning("No Key", "Please load the encryption key first.")
            return

        file_path = self.filepath_entry.get()
        if not file_path:
            messagebox.showwarning("No File", "Please select a file to decrypt.")
            return

        try:
            fernet = Fernet(self.key)
            with open(file_path, "rb") as file:
                encrypted_data = file.read()

            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception as e:
                messagebox.showerror(
                    "Decryption Error",
                    f"Failed to decrypt file: Invalid Key or Corrupted Data. ({e})",
                )
                self.update_status("Decryption failed (Invalid Key/Corrupted Data).")
                return

            # Determine decrypted file name (remove .encrypted if present)
            if file_path.endswith(".encrypted"):
                decrypted_file_path = file_path[:-len(".encrypted")]
            else:
                decrypted_file_path = file_path + ".decrypted"  # Fallback if suffix not found

            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)

            messagebox.showinfo(
                "Decryption Successful",
                f"File decrypted successfully!\nSaved as: {os.path.basename(decrypted_file_path)}",
            )
            self.update_status(f"File decrypted: {os.path.basename(file_path)}.")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt file: {e}")
            self.update_status("Decryption failed.")

    def update_status(self, message):
        """Updates the status bar message."""
        self.status_bar.config(text=message)
        self.master.update_idletasks()  # Refresh the GUI


def main():
    root = tk.Tk()
    app = AdvancedEncryptionTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
