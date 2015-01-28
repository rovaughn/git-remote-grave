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
  
    $ git clone grave::https://filegrave.com/username/private-repo
    Cloning into 'private-repo'...
    Checking connectivity... done.

Using a key
-----------

If GRAVEKEY is set to a filename, then that file is read to determine the key;
otherwise, it is assumed the key is in `.gravekey` under the repository's root
directory.

The contents of keyfile will be hashed by SHA256 to derive the key.  Leading
and trailing whitespace is ignored, so that you don't have to worry if there
is a trailing newline.

If you want to generate a new key, you can use the following command.

    git-remote-grave create-key keyfile

It will create keyfile with 600 permissions and populate it with a randomly
generated hex string.

Encryption
----------

The package [golang.org/x/crypto/nacl/secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox),
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


