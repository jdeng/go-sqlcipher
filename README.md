# go-sqlcipher
SQL cipher go binding (see sqlite3.c for version information)

```*.go``` are from https://github.com/mutecomm/go-sqlcipher

```sqlite3.c``` is a legacy version which can work with WeChat android version.

See LICENSE.orig, README.orig for more information. Please note this packages depends on OpenSSL 1.0.x branch.

# Windows users
A few minor tweaks are needed: remove "-lcrypto" and add the include directories and macros in sqlite3_windows.go.
 
# Example
See ```cmd```.


