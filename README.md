## Java File Encryptor 

The Objective of this project was to learn how to use the Java Cryptography Extension (JCE) to perform symmetric file encryption and decryption. Additionally password-based encryption and implementation for changes in recommended key lengths and algorithms were also added. 

## Folder Structure

The project contains two folders 

- `src`: the folder has the FileEncryptor.java where majority of the project functionality resides and a Util.java file with some utility fuctions.
- `resources`: this folder is used to store all the input and output files i.e. the plaintext and ciphertext files.

## How to run

### Step 1: Compilation

Enter the comamnds below and after navigating to the `src` folder of the project through the *terminal*.
``` bash
javac FileEncryptor.java Util.java
```

### Step 2: Create Plaintext

Create or copy a pre-existing plaintext file and make sure it has some content within. Save it in your desired location.
``` bash
echo "This is a plaintext file" >> plaintext.txt
```
**Note:** The program can encrypt any file type, not limited to just `.txt`

### Step 3: Encryption

``` bash
java FileEncryptor <action> [algorithm] [keyLength] <password> <plaintext> <ciphertext>
```

When encrypting a file the user has the option to specify the *Algorithm* and *key length*. However, these are only optional arguments. If they are not specified then the default values (AES with 128 bits) will be used to perform the encryption on the file. 

Currently the program accepts the AES and Blowfish algorithms and its valid keylengths. 

The encryption will also be successful if either the Algorithm or Key length is specified as the default value will be applied to the property that is not specified.

e.g. 
``` bash
java FileEncryptor enc p@ssw0rd plaintext.txt ciphertext.txt
```
``` bash
java FileEncryptor enc 192 p@ssw0rd plaintext.txt ciphertext.txt
```
``` bash
java FileEncryptor enc AES p@ssw0rd plaintext.txt ciphertext.txt
```
``` bash
java FileEncryptor enc Blowfish 448 p@ssw0rd plaintext.txt ciphertext.txt
```

### Step 4: Decryption

``` bash
java FileEncryptor <action> <password> <ciphertext> <plaintext> 
```

The same password must be used when decrypting a previously encrypted file. 

e.g.
``` bash
java FileEncryptor dec p@ssw0rd ciphertext.txt decrypted.txt
```

### Query Metadata

To query the metadata on an encrypted file enter the following command below

``` bash
java FileEncryptor info ciphertext.txt
```
