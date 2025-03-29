#Copyright 2025 yo525
#SPDX-License-Identifier: Apache-2.0

# Import necessary libraries for file handling, GUI operations, encryption, and hashing
from os import getcwd, walk, makedirs, rename, unlink
from os.path import join, split, exists, isfile, getsize
from easygui import fileopenbox, diropenbox, ccbox, passwordbox, boolbox, filesavebox
from hashlib import sha3_512
from tkinter.messagebox import showwarning, showinfo
from tkinter import END, Listbox, Y, X, Tk, BOTTOM, HORIZONTAL, VERTICAL, RIGHT
from tkinter.ttk import Scrollbar, Frame, Button
from Crypto.Cipher.AES import new, MODE_GCM
from Crypto.Protocol.KDF import scrypt
from secrets import token_bytes, token_hex
from linecache import getline, clearcache
from shutil import rmtree
from sys import exit

# Define the path for the text file that will store the encrypted data
ruta_file = 'AegisVault.txt'

def act_txt(directorio: str | None = getcwd(), paths: list | None = None, delete: bool = False) -> None:
    """
    Encrypts files at the specified directory and saves them to the designated text file.
    
    Args:
        directorio (str | None): The directory to search for files. Defaults to the current working directory.
        paths (list | None): List of file paths to process. If None, files will be found in 'directorio'.
        delete (bool): If True, deletes original files after processing.
    """
    try:
        # If a directory is provided, find all paths of files within
        if directorio is not None:
            paths = caminar(directorio)

        # Open the designated file to append the encrypted paths and contents
        with open(ruta_file, 'a') as f:
            for i in paths:
                # Encrypt and write the file path and contents to the text file
                f.write(cifrar(password, i.encode()) + '\n')
                f.write(cifrar(password, open(i, 'rb').read()) + '\n')
                # Optionally delete the original file and replace it with random data
                if delete == False:
                    shred(i)

        # If both directory and delete options are set, remove the directory
        if directorio != False and delete == False:
            rmtree(directorio)

        # Update main window with new items added
        act_ventana_main_add(paths)
        paths = None
    
    except Exception as e:
        showwarning("Error1", f"An error occurred while processing files: {str(e)}")

def shred(path:str):
    """
    Shreds a file by overwriting its contents with random data multiple times and then deleting it.

    Args:
        path (str): The path to the file to be shredded.

    Returns:
        bool: True if the file was successfully shredded, False otherwise.
    """

    # Check if the file exists
    if not isfile(path):
        return False
    
    lenght = getsize(path)

    # Overwrite the file with random data multiple times
    for _ in range(3):
        f = open(path, "wb")
        data = token_bytes(lenght) # Generate random data of the same length as the file
        f.write(data) # Write the random data to the file
        f.close()
    
    name = token_hex(16) # Generate a random name for the file
    rename(path, name)
    unlink(name) # Delete the renamed file
    return True


def act_ventana_main_add(elementos:list) -> None:
    """
    Updates the main GUI list with new elements.

    Args:
        elementos (list): List of new elements to add to GUI.
    """
    global lista
    for i in elementos:
        lista.insert(END, i)  # Insert each new element into the GUI list
    elementos = None

def caminar(dir:str) -> list:
    """
    Walks through the specified directory and collects all file paths.

    Args:
        dir (str): Directory path to search.

    Returns:
        list: List of file paths found in the directory.
    """
    files = []
    for dirpath, dirnames, filenames in walk(dir):
        for i in filenames:
            files.append(join(dirpath, i))  # Add each file's full path to the list

    return files

def descifrar(clave:bytes, informacio:bytes) -> bytes|(bool|str):
    """
    Decrypts the provided information using the supplied key.

    Args:
        clave (bytes): The decryption key.
        informacio (str): The information to decrypt (hex-encoded).

    Returns:
        bytes: Decrypted message if successful, otherwise an error message.
    """
    informacion = bytes.fromhex(informacio)  # Convert from hex
    sal = informacion[32:48]
    # Derive the encryption key from password and salt
    key = scrypt(clave, sal, 16, N=2**14, r=8, p=1)
    tag = informacion[16:32]
    nonce2 = informacion[0:16]
    hmac = informacion[48:112]
    message = informacion[112:]

    # Validate the message with HMAC
    check = sha3_512(message + nonce2 + tag + sal).digest() == hmac
    if check:
        cipher = new(key, MODE_GCM, nonce=nonce2)
        msj = cipher.decrypt_and_verify(message, tag)  # Decrypt the message
        return msj
    else:
        return (False, 'The message was corrupted')  # Indicate failure

def cifrar(clave:bytes, informacion:bytes) -> str:
    """
    Encrypts the provided information using the supplied key.

    Args:
        clave (bytes): The encryption key.
        informacion (bytes): The data to encrypt.

    Returns:
        str: A hex-encoded string of the encrypted data, nonce, tag, and HMAC.
    """
    sal = token_bytes(16)  # Generate a unique salt
    key = scrypt(clave, sal, 16, N=2**14, r=8, p=1)  # Derive key
    cipher = new(key, MODE_GCM)  # Initialize cipher
    ciphertext, tag = cipher.encrypt_and_digest(informacion)  # Encrypt the data
    hmac = sha3_512(ciphertext + cipher.nonce + tag + sal).digest()  # Generate HMAC
    return bytes.hex(cipher.nonce + tag + sal + hmac + ciphertext)  # Return combined result

def password_check(data1:str, data2:str) -> bool:
    """
    Validates the entered password by decrypting stored data.

    Args:
        data1 (str): The encrypted password from storage.
        data2 (str): The password input provided by the user.

    Returns:
        bool: True if the password is valid, otherwise False.
    """
    try:
        # Compare the hashed value of decrypted data with the hashed input password
        if sha3_512(descifrar(data2, data1)).hexdigest() == sha3_512(data2.encode()).hexdigest():
            return True
        else:
            return False
    except:
        return False  # Return False on any error

def select_all() -> None:
    """Selects all items in the GUI list."""
    lista.selection_set(0, END)  # Select all items in the list

def delete_selection() -> None:
    """
    Deletes selected items from the GUI list and the data file.

    This function handles the deletion and updates the text file accordingly.
    """
    indices = lista.curselection()  # Get the indices of selected items
    result = []
    for i in sorted(indices, reverse=True):
        result.append((((i + 1) * 2) + 1))  # Calculate lines to delete (paths)
        result.append(((i + 1) * 2))  # Calculate lines to delete (contents)
    delete_txt(result)  # Remove specified lines from text file
    for i in sorted(indices, reverse=True):
        lista.delete(int(i))  # Remove items from GUI list

def anadir() -> None:
    """
    Prompts the user to select files or a directory to add to the system.

    Supports either multiple files or a single directory upload,
    and offers the option to delete the original files after processing.
    """
    try:
        opcion = ccbox('Do you want to add a file/s or a directory?', 'Select', choices=('Files/s', 'Directory'))
        
        # Handle adding files
        if opcion == True:
            paths = fileopenbox(title='Add file', multiple=True)
            if paths is not None:
                opcion2 = boolbox('Do you want to delete the items from your files?', choices=('No', 'Yes'), default_choice='Yes')
                act_txt(None, paths, opcion2)  # Process the files
        
        # Handle adding directory
        else:
            paths = diropenbox(title='Add directory')
            if paths is not None:
                opcion2 = boolbox('Do you want to delete the items from your files?', choices=('No', 'Yes'), default_choice='Yes')
                act_txt(paths, delete=opcion2)  # Process the directory
            
    except Exception as e:
        showwarning("Error2", f"An error occurred while adding files: {str(e)}")

def descargar() -> None:
    """
    Downloads selected files from the data file to a specified location.

    The user can choose to download files to their original or a new path.
    """
    global lista
    try:
        indices = lista.curselection()  # Get selected indices from list
        opcion2 = boolbox('Download files to the default path (is the path that appears as name)?', choices=('No', 'Yes'), default_choice='Yes')
        
        if opcion2:
            directory = diropenbox('Select new path')  # Ask user for download directory
            if directory is None:
                return

        for i in sorted(indices, reverse=True):
            # Existing decryption process
            pa = descifrar(password, getline(ruta_file, ((i + 1) * 2))).decode()  # Decrypt path
            clearcache()
            
            # Determine where to save the files
            if not opcion2:
                paths = pa
                directory = split(paths)[0]
            else:
                paths = join(directory, split(pa)[1])
            
            info = descifrar(password, getline(ruta_file, ((i + 1) * 2) + 1))  # Decrypt content
            clearcache()
            if exists(directory):
                with open(paths, 'wb') as f:
                    f.write(info)  # Write the decrypted content to a file
            else:
                makedirs(directory)  # Create directory if it doesn't exist
                with open(paths, 'wb') as f:
                    f.write(info)

            lista.delete(int(i))  # Remove from GUI list

        result = []
        for i in sorted(indices, reverse=True):
            result.append((((i + 1) * 2) + 1))
            result.append(((i + 1) * 2))
        delete_txt(result)  # Update the text file by removing entries

    except Exception as e:
        showwarning("Error3", f"An error occurred while downloading files: {str(e)}")

def delete_txt(items:list) -> None:
    """
    Deletes specified lines in the text file where items were stored.

    This function overwrites the original text file, excluding the specified entries.

    Args:
        items (list): Indices of items to delete from the text file.
    """
    ruta_file2 = bytes.hex(token_bytes()) + '.txt'  # Create a temporary file name
    with open(ruta_file, "r") as f:
        contador = len(f.readlines())  # Count total lines in the text file

    # Write all lines except for the specified items
    with open(ruta_file2, "w") as f:
        for line in range(1, contador + 1):
            if line not in items:
                f.write(getline(ruta_file, line))

     
    shred(ruta_file) # Remove the original file
    rename(ruta_file2, ruta_file)  # Rename the temporary file to the original file name
    clearcache()

def change_password() -> None:
    """
    Allows the user to change their current password.

    The user must first delete all contents in the database before changing the password.
    """
    global password
    try:
        if len(open(ruta_file, 'r').readlines()) > 2:
            showwarning('Error4', 'In order to change the password you have to first download/delete all the content in the database')
            return

        control = False
        passwor = ''
        while control == False and passwor is not None:
            passwor = passwordbox(title='AegisVault')
            control = password_check(open(ruta_file, 'r').readline().rstrip(), passwor)  # Validate original password

        if control:
            control = False
            passwo = ''
            while control == False and passwo is not None:
                passwo = passwordbox(title='AegisVault', msg='Enter the new password')
                passw = passwordbox(title='AegisVault', msg='Reenter the new password')
                if passw == passwo and passwo is not None:
                    password = passw  # Update the password
                    # Encrypt and save the new password
                    with open(ruta_file, 'w') as f:
                        f.write(cifrar(password, password.encode()) + '\n')
                    showinfo('Password change', message='Password changed successfully')
                    control = True
                elif passwo is None:
                    control = True  # Exit if user cancels
                else:
                    showinfo(message='Both passwords do not match')

    except Exception as e:
        showwarning("Error5", f"An error occurred while changing the password: {str(e)}")

def backup() -> None:
    """
    Provides functionality for exporting or importing backups of the database.

    Users have the option to export the database with or without an additional encryption layer.
    """
    try:
        opcion = ccbox('You want to import or export the backup', 'Select', choices=('Import', 'Export'))
        
        if not opcion:
            opcion2 = boolbox('Do you want to export the database with an extra layer of encryption?', 'Select', choices=('Yes', 'No'))
            if not opcion2:
                ruta = filesavebox(filetypes='.txt', default='AegisVault.txt')
                with open(ruta, 'wb') as f:
                    with open(ruta_file, 'rb') as ff:
                        texto = ff.read()  # Read content from the original DB file
                        f.write(texto)  # Save to the specified backup file
                showinfo('Success', 'The export of the database was successful')
            elif opcion2:
                # Export with encryption
                ruta = filesavebox(filetypes='.enc', default='AegisVault.txt.enc')
                if ruta is None:
                    return
                opcion3 = ccbox('Do you want to encrypt with your default password or with a new one?', choices=('Default', 'New one'))
                if opcion3:
                    with open(ruta, 'w') as f:
                        with open(ruta_file, 'rb') as ff:
                            texto = cifrar(password, ff.read())  # Encrypt and save
                            f.write(texto)
                    showinfo('Success', 'The export of the database was successful')
                elif not opcion3:
                    password2 = passwordbox()  # Prompt for new password
                    if password2 is None:
                        return
                    with open(ruta, 'w') as f:
                        with open(ruta_file, 'rb') as ff:
                            texto = cifrar(password2, ff.read())  # Encrypt and save
                            f.write(texto)
                    showinfo('Success', 'The export of the database was successful')
            texto = None
        # Import functionality
        elif opcion:
            showwarning('WARNING', 'Warning: The actual database is going to be replaced due to the import of a new one; all information will be deleted. Ensure there is no sensitive data.')
            ruta = fileopenbox(filetypes=['*.txt', '*.enc'], default='*.txt')
            if ruta is None:
                return
            if split(ruta)[-1].split('.')[-1] == 'txt':
                with open(ruta_file, 'wb') as f:
                    with open(ruta, 'rb') as ff:
                        texto = ff.read()  # Read content from the new DB file
                        f.write(texto)
                showinfo('Success', 'The import of the database was completed successfully')
            elif split(ruta)[-1].split('.')[-1] == 'enc':
                password2 = passwordbox('Enter the password used to encrypt the database backup')
                if password2 is None:
                    return
                with open(ruta_file, 'wb') as f:
                    with open(ruta, 'r') as ff:
                        texto = descifrar(password2, ff.read())  # Decrypt and save
                        f.write(texto)
                showinfo('Success', 'The import of the database was completed successfully')

            opcion4 = boolbox('Do you want to delete the database backup?', 'Select', choices=('Yes', 'No'))
            if opcion4:
                shred(ruta)

            showinfo('Restart', 'To apply changes, you must restart the program.')
            texto = None
            exit()  # Terminate the program

    except Exception as e:
        showwarning("Error6", f"An error occurred during backup: {str(e)}")

def ventana_main() -> None:
    """
    Creates and displays the main GUI for the application, allowing user interaction
    to perform various tasks with the data loaded from the text file.
    """
    global lista
    window = Tk()  # Create the main window
    window.title('AegisVault')

    frame = Frame()  # Create a frame to hold the listbox and scrollbars
    scrollbar = Scrollbar(frame, orient=VERTICAL)  # Vertical scrollbar
    hscrollbar = Scrollbar(frame, orient=HORIZONTAL)  # Horizontal scrollbar

    # Create a listbox to display encrypted items
    lista = Listbox(frame, selectmode="extended", yscrollcommand=scrollbar.set, xscrollcommand=hscrollbar.set)

    # Configure the scrollbar's command
    scrollbar.config(command=lista.yview)
    hscrollbar.config(command=lista.xview)
    scrollbar.pack(side=RIGHT, fill=Y)  # Pack vertical scrollbar
    hscrollbar.pack(side=BOTTOM, fill=X)  # Pack horizontal scrollbar
    lista.pack(expand=True, fill="both")  # Pack listbox
    frame.pack(expand=True, fill="both")  # Pack frame

    # Load contents from the text file and decrypt to display in the list
    with open(ruta_file, 'r') as f:
        init = 1
        for i in f.readlines():
            if init % 2 == 0:
                lista.insert(END, descifrar(password, i.rstrip()).decode())  # Insert decrypted content
            init += 1
    
    # Create a frame for action buttons
    frame2 = Frame()
    Button(frame2, text='Select all', command=select_all).grid(row=1, column=1, padx=8, pady=10)
    Button(frame2, text='Delete selection', command=delete_selection).grid(row=1, column=2, padx=8, pady=10)
    Button(frame2, text='Add asset', command=anadir).grid(row=1, column=3, padx=8, pady=10)
    Button(frame2, text='Download selection', command=descargar).grid(row=1, column=4, padx=8, pady=10)
    Button(frame2, text='Change password', command=change_password).grid(row=1, column=5, padx=8, pady=10)
    Button(frame2, text='Backup', command=backup).grid(row=1, column=6, padx=8, pady=10)
    frame2.pack()

    window.update()  # Update window to reflect latest changes
    window.minsize(width=window.winfo_width(), height=window.winfo_height())  # Set minimum size
    window.mainloop()  # Start the GUI event loop

def main() -> None:
    """
    Main entry point for the program. Initiates password prompt and launches the main window.
    """
    global password

    control = False
    while not control:
        password = passwordbox(title='AegisVault')  # Prompt for password
        if password is None:  # Exit if user cancels
            exit()
        control = password_check(open(ruta_file, 'r').readline().rstrip(), password)  # Check the password

    ventana_main()  # Show main application window

if __name__ == '__main__':
    try:
        main()  # Start the program
    except Exception as e:
        showwarning(message=e)  # Handle and shows any exceptions that arise
