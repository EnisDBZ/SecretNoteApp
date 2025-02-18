import tkinter
from tkinter import END
from tkinter import messagebox
import base64
from tkinter.messagebox import OKCANCEL

from PIL import Image,ImageTk


# Window
window = tkinter.Tk()
window.title("Secret Note")
window.minsize(height=760,width=480)
window.config(pady=30,padx=30)
#General Settings
FONT =("Times",20,"bold")
# Encode and Decodes
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = (ord(clear[i]) + ord(key_c)) % 256
        enc.append(enc_c)
    return base64.urlsafe_b64encode(bytes(enc))

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc)
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + enc[i] - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

'''
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode())

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc)
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
'''




# UI
image = Image.open("Images/topsecret175.png")
#new_image = image.resize((175,175))
#new_image.save("topsecret175.png")
image = ImageTk.PhotoImage(image)


label_image = tkinter.Label(window,image=image)
label_image.pack()


label_title = tkinter.Label(text="Enter your title",font=FONT)
label_title.pack()

entry_title = tkinter.Entry()
entry_title.pack()

label_secret = tkinter.Label(text="Enter your secret",font=FONT)
label_secret.pack()

text_secret = tkinter.Text(height=10)
text_secret.pack()

label_master_key = tkinter.Label(text="Enter the master key",font=FONT)
label_master_key.pack()

entry_master_key = tkinter.Entry(width=100)
entry_master_key.pack()


def save_and_encrypt():
    secret_input = text_secret.get("1.0",END)
    title_input = entry_title.get()
    secret_key = entry_master_key.get()
#encryption


    if len(secret_input) == 0 or len(title_input) == 0 or len(secret_key) == 0 :
        messagebox.showinfo("Warning","Boxes can't be left empty!")
    else:
        #encryption
        encrypted_message = encode(secret_key,secret_input)


        try:
            with open("mysecretnotes.txt", "a") as file:
                file.write(f"\n{title_input}\n{encrypted_message}")
       # with open("mysecretnotes.txt", "a") as file:
       #     file.write("\n")
       # with open("mysecretnotes.txt", "a") as file:
       #     file.write(secret_input)
        except FileNotFoundError:
            with open("mysecretnotes.txt","w") as file:
                file.write(f"\n{title_input}\n{encrypted_message}")
        # Ekranı temizlemek için
        finally:
            text_secret.delete("1.0",END)
            entry_title.delete(0,END)
            entry_master_key.delete(0,END)

def decryptMethod():
        encrypted_message = text_secret.get("1.0",END)
        secret_key = entry_master_key.get()

        if len(encrypted_message) == 0 or len(secret_key) == 0 :
            messagebox.showinfo("Warning", "Boxes can't be left empty!")
        else:
            # decyrption
            decode_message = decode(secret_key,encrypted_message)
            text_secret.delete("1.0",END)
            text_secret.insert("1.0",decode_message)

btn_encrypt = tkinter.Button(text="Save and Encrypt",command=save_and_encrypt)
btn_encrypt.config()
btn_encrypt.place(x= 270,y= 500)

btn_decrypt = tkinter.Button(text="Decrypt", command=decryptMethod)
btn_decrypt.place(x = 290, y = 540)







window.mainloop()