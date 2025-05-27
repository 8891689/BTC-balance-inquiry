# Program Functionality
  Amount_Query is an offline blockchain amount queryer used to query the balance of cryptocurrency addresses (mainly BTC and ETH types). It supports entering private keys, public keys or (values ​​not encoded into addresses) Hash160 automatically calculated into addresses, or directly entering addresses and then executing queries. The accuracy depends on the data document. Addresses can be queried in batches, and public key queries are in another library.

# Core Features
1. Multi-Database Support: The program can automatically scan the current directory for all .txt files to use as databases, or you can manually specify one or more database files using the -f option.
2. Multiple Input Types:
3. Direct address query.
  Derive and query BTC (P2PKH, P2WPKH, P2SH-P2WPKH) and ETH addresses from WIF or HEX formatted private keys.
Derive and query BTC and ETH addresses from HEX formatted public keys (compressed or uncompressed).
Derive and query BTC addresses from HEX formatted Hash160.
4. Batch Processing: Allows reading a list of addresses from an input file and outputting the query results to another file.
  Amount Formatting: BTC amounts are displayed in the standard format with 8 decimal places.
5. Database File Format
  Database files (defaulting to .txt files) should adhere to the following format, with one entry per line:
<Address><TAB><Amount_in_Satoshi_units>

6. Mainly dependent on, you need to download the latest address with the balance data file (the one with the value at the end), so that the program can query accurately, the newer the more accurate.

http://addresses.loyce.club/

For example:
```
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa	100000000
0x742d35Cc6634C0532925a3b844Bc454e4438f44e	500000000000000000
```
```
<Address>: The cryptocurrency address.
<TAB>: A single tab character as a separator.
<Amount_in_Satoshi_units>: For BTC, this is the amount in Satoshis (integer).
For ETH, it's typically in Wei. The program currently formats BTC amounts primarily.
```
# Usage
The program will automatically scan for .txt files in the current directory as databases (unless -f is specified).
Usage:
```
./aq -f
Error: -f option requires at least one database filename.
Program will automatically scan for .txt files in the current directory as databases (unless -f is specified).
Usage:
  ./aq [-f <datafile1> [<datafile2> ...]] (Interactive mode)
  ./aq [-f <datafile1> ...] <address>
  ./aq [-f <datafile1> ...] -k <private_key_WIF_or_HEX>
  ./aq [-f <datafile1> ...] -p <public_key_HEX>
  ./aq [-f <datafile1> ...] -h <Hash160_HEX>
  ./aq [-f <datafile1> ...] <input_file> <output_file> [-x]
Options:
  -f <file_list> : Specify one or more database files for query (overrides auto-scan).
  -x             : (Batch mode) Output only found addresses, without amount.
```

Examples:
Interactive Mode (auto-scans databases):
```
./aq
```
Then enter addresses to query.
Direct Address Query (auto-scans databases):
```
./aq bc1qmt2m7np4aey7639h3aapj3wdvjql85v6fgg9dj
Address: bc1qmt2m7np4aey7639h3aapj3wdvjql85v6fgg9dj
Amount: 0.00312000 BTC

./aq -p 0200057b53e8004f82b1e7ed9c2989b55e9969973d8413318ea2e56cca39b4e471
Address: bc1qmt2m7np4aey7639h3aapj3wdvjql85v6fgg9dj
Amount: 0.00312000 BTC

./aq -h 751e76e8199196d454941c45d1b3a323f1433bd6
Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
Amount: 0.00123456 BTC
Address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
Amount: 0.00123654 BTC
Address: 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
Amount: 0.00000011 BTC

./aq -k 0000000000000000000000000000000000000000000000000000000000000001
Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
Amount: 0.00123456 BTC

./aq -k KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
Amount: 0.00123456 BTC


The error about ETH is for convenience, it is actually the amount of ETH.
./aq -k 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
Address: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
Amount: 0.00000011 BTC


```
Query from Private Key (specifying database files db1.txt and db2.txt):
```
./aq -f db1.txt db2.txt -k Kx...
```
Batch Query (reads from addresses.txt, outputs to results.txt, auto-scans databases):
```
./aq addresses.txt results.txt
```
Batch Query (outputs addresses only, auto-scans databases):
```
./aq addresses.txt results_no_amount.txt -x
```
# Compilation Guide

You will need a C compiler (like GCC or Clang). Ensure all dependent source files (.c files) and header files (.h files) are in the same directory or within the compiler's include path.

Linux / macOS (using GCC or Clang):

In your terminal, navigate to the directory containing all source files and execute:
```
gcc amount_query.c sha256.c ripemd160.c secp256k1.c keccak256.c bech32.c base58.c -O3 -o aq
```
Or using Clang:
```
clang amount_query.c sha256.c ripemd160.c secp256k1.c keccak256.c bech32.c base58.c -O3 -o aq
```
-O3: Enables a high level of optimization.
-o Amount_Query: Specifies the output executable name as aq.


Windows (using MinGW-w64 GCC):
If you have MinGW-w64 (a GCC toolset for Windows) installed, you can execute a command similar to the Linux/macOS one in the MinGW terminal or command prompt:
```
gcc amount_query.c sha256.c ripemd160.c secp256k1.c keccak256.c bech32.c base58.c -O3 -o aq.exe
```
(On Windows, executables typically have the .exe suffix).

Windows (using Microsoft Visual Studio - MSVC):

Open Visual Studio.
```
Create a new empty C++ project (or C project if available).
Add all .c and .h files to your project.

Ensure the project is set to compile C code (if you created a C++ project, it usually auto-detects for .c files, but settings might need adjustment).

MSVC might issue warnings or errors for certain POSIX-specific functions (like strcasecmp or strdup).
For strcasecmp, you can use _stricmp.

For strdup, you can use _strdup.

You might need to use conditional compilation in your code to handle these differences or find compatible implementations.
The current code uses strings.h mainly for strcasecmp, and scan_directory_for_data_files under _WIN32 already uses _strdup.
Build (Generate Solution).
```
# Cross-Platform Notes:

Directory Scanning: The scan_directory_for_data_files function uses conditional compilation (#ifdef _WIN32) to handle directory traversal differently for Windows and POSIX systems.

strcasecmp: POSIX systems usually provide strcasecmp in <strings.h>. The Windows MSVC equivalent is _stricmp in <string.h>. MinGW GCC might provide strcasecmp.

strdup: POSIX systems usually provide strdup in <string.h>. The Windows MSVC equivalent is _strdup in <string.h>.
If you encounter compilation issues, check the compiler's error output, which usually indicates missing functions or header files.

# Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```
# 📜 Disclaimer
⚠️ Reminder: Do not input real private keys on connected devices!

This tool is provided for learning and research purposes only. Please use it with an understanding of the relevant risks. The developers are not responsible for financial losses or legal liability -caused by the use of this tool.

