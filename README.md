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
java FileEncryptor enc p@ssw0rd plaintext.txt ciphertext.enc
```
``` bash
java FileEncryptor enc 192 p@ssw0rd plaintext.txt ciphertext.enc
```
``` bash
java FileEncryptor enc AES p@ssw0rd plaintext.txt ciphertext.enc
```
``` bash
java FileEncryptor enc Blowfish 448 p@ssw0rd plaintext.txt ciphertext.enc
```

### Step 4: Decryption

``` bash
java FileEncryptor <action> <password> <ciphertext> <plaintext> 
```

The same password must be used when decrypting a previously encrypted file. 

e.g.
``` bash
java FileEncryptor dec p@ssw0rd ciphertext.enc decrypted.txt
```

### Query Metadata

To query the metadata on an encrypted file enter the following command below

``` bash
java FileEncryptor info ciphertext.enc
```

## Output

All data used for encryption, decryption and authentication is printed out to the console for testing purposes.

### Encryption output

``` bash
<---------------------------------------->
Secret Key: 4v3GURNUyxpT+wQ7V+7lnA==
Init Vector: Myg7C+La5xo7A9czkMvSlA==
Salt: FbXNYM6ofed26t/GY27/tQ==
Mac Key: XgYmnjFXo0aKTxGMc00uVHoeNYvXBTwRV5teJM8TitU=
Mac salt: 3X0+fVGznlZQtXN+4QW7aA==
Computed Mac: yiB/ldtDwyKMt4vcPfja+TC9guC+xzgoexFj+ciC6k8=
<---------------------------------------->
INFO: Encryption finished, saved at ciphertext.enc
```

### Decryption output
``` bash
<---------------------------------------->
Secret Key: 4v3GURNUyxpT+wQ7V+7lnA==
Init Vector: Myg7C+La5xo7A9czkMvSlA==
Salt: FbXNYM6ofed26t/GY27/tQ==
Mac Key: XgYmnjFXo0aKTxGMc00uVHoeNYvXBTwRV5teJM8TitU=
Mac salt: 3X0+fVGznlZQtXN+4QW7aA==
Computed Mac: yiB/ldtDwyKMt4vcPfja+TC9guC+xzgoexFj+ciC6k8=
Given Mac: yiB/ldtDwyKMt4vcPfja+TC9guC+xzgoexFj+ciC6k8=
<---------------------------------------->

INFO: Authentication passed, file integrity maintained
INFO: Decryption complete, open decrypted.txt
```

### Info Query output
``` bash 
Metadata for file: resources/ciphertext.enc

<---------------------------------------->
Algorithm: AES
Key length: 128
Blocksize: 128
<---------------------------------------->
Init Vector: 2VZe+7ogcuQfOia7mbd38w==
Salt: zVhJUB7OfMrw8b6si4L2AQ==
Mac salt: i9iRZ+Mzb2LxNx9rptCzQQ==
Computed Mac: fqbGjJGIeFaqA2TMmBTFrdjgPEEIk57lIV0dUhevxSM=
<---------------------------------------->
```