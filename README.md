git-remote-grave
================

Adds a protocol to git for pushing and fetching encrypted repositories.

Example with a local file:

    $ git remote add backup grave::/mnt/external-disk/backup
    $ git push --all backup
    git fast-import...
    git repack -a -d -f...
    git gc...
    Packing and compressing...
    Encrypting...
    Pushing...
    To grave::/mtn/external-disk/backup
     * [new branch]      master -> master
    $ git fetch backup

Example with HTTP:

    $ git clone grave::https://example.com/username/private-repo
    Cloning into 'private-repo'...
    Checking connectivity... done.

How do you make something like this?
------------------------------------

I did a write-up [here](https://rovaughn.github.io/2015-2-9.html).

Using a key
-----------

The encryption key is produced by taking the SHA256 hash of a keysource.  The
keysource can be of any length; leading and trailing whitespace is stripped so
that trailing newlines are not an issue.

If a key has not been set for the repository, then git-remote-grave will
interactively determine the key.  In all cases, the keysource will be ultimately
copied to `.git/grave/remotename/key` with 600 permissions.

Three options are provided:

1. Enter the keysource by typing a string.  The characters will not be echoed,
   like a password.
2. Specify an existing file as the keysource.
3. Randomly generate a new key.  Most secure.  Only when pushing.

You can also set the environment variable `GRAVE_KEYFILE` to a file to use as
the keysource.  This may be useful in scripts.

Encryption
----------

The package
[golang.org/x/crypto/nacl/secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox),
which is a port of [DJB's NaCl](http://nacl.cr.yp.to/), is used to encrypt and
authenticate repositories.  The nonce is randomly generated every time the
repository is encrypted, so that two identical repositories encrypt to two
completely different blobs of data.  However, git-remote-grave knows if the
unencrypted repository actually changed, and will skip a push or fetch if it's
unecessary.

Packing and compression
-----------------------

After creating an encrypted repository for the first time,
`git repack -a -d -f` and `git gc` are run.  All the times after that, just
`git repack` and `git gc` are run.

The repository is then packed with tar and compressed.

A tar archive of an empty git repository is used as the dictionary in the
compression, improving the ratio.  The algorithm used is
[golang's DEFLATE library](https://golang.org/pkg/compress/flate/) on
maximum compression level.

The combination of these techniques typically reduces the repository size by
78%.

