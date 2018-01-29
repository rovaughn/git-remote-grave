//go:generate ./generate-bindata
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gcmurphy/getpass"
	"github.com/rovaughn/git-remote-grave/tarpack"
	"io"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	pathlib "path"
	"strconv"
	"strings"
)

var (
	errConflict = fmt.Errorf("Push conflict")
)

func userprintf(format string, a ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, format, a...); err != nil {
		panic(err)
	}
}

func debugf(format string, a ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, format, a...); err != nil {
		panic(err)
	}
}

var (
	tty       *os.File
	ttyReader *bufio.Reader
	localDir  string
)

func prompt(message string) (string, error) {
	var err error

	userprintf("%s", message)

	line, err := ttyReader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

func promptSecret(message string) (response string, err error) {
	return getpass.GetPassWithOptions(message, 0, 64)
}

type fetchResult struct {
	initial         bool
	tempDir         string
	eTag            string
	key             *key
	unencryptedHash []byte
}

var (
	authorization *neturl.Userinfo
)

type reqGenerator func(*neturl.Userinfo) (*http.Request, error)

func authorizedRequest(reqGenerator reqGenerator) (*http.Response, error) {
	client := &http.Client{}

	req, err := reqGenerator(authorization)
	if err != nil {
		return nil, err
	}

	username, password, _ := req.BasicAuth()

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusForbidden {
		res.Body.Close()

		if username != "" && password != "" {
			return nil, fmt.Errorf("Forbidden")
		}

		userprintf("The server responded with %d Forbidden.\n", res.StatusCode)

		if username == "" {
			username, err = prompt("Username: ")
			if err != nil {
				return nil, err
			}
		}

		if password == "" {
			password, err = promptSecret("Password: ")
			if err != nil {
				return nil, err
			}
		}

		authorization = neturl.UserPassword(username, password)

		req, err = reqGenerator(authorization)
		if err != nil {
			return nil, err
		}

		req.SetBasicAuth(username, password)

		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}

		if res.StatusCode == http.StatusForbidden {
			userprintf("The server responded with %d Forbidden.\n", res.StatusCode)

			return nil, fmt.Errorf("Forbidden")
		}
	}

	return res, nil
}

type key struct {
	source []byte
	key    [32]byte
}

func createKey(source []byte) (*key, error) {
	trimmedSource := bytes.TrimSpace(source)

	hasher := sha256.New()

	if _, err := hasher.Write(trimmedSource); err != nil {
		return nil, err
	}

	key := &key{
		source: source,
	}

	hasher.Sum(key.key[0:0:32])

	return key, nil
}

type keyOption struct {
	description string
	procedure   func() (*key, error)
}

var existingFileOption = keyOption{
	description: "Use the contents of an existing file.",
	procedure: func() (*key, error) {
		filename, err := prompt("Filename (contents can be of any length): ")
		if err != nil {
			return nil, err
		}

		source, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		return createKey(source)
	},
}

var typedInStringOption = keyOption{
	description: "Use a typed-in string.",
	procedure: func() (*key, error) {
		userprintf("Type a string of any length up to 64 characters.\n")
		source, err := promptSecret("Key source: ")
		if err != nil {
			return nil, err
		}

		return createKey([]byte(source))
	},
}

var generateNewKeyOption = keyOption{
	description: "Randomly generate a new key.",
	procedure: func() (*key, error) {
		sourceBytes := make([]byte, 32)

		if _, err := rand.Read(sourceBytes); err != nil {
			return nil, err
		}

		source := make([]byte, hex.EncodedLen(len(sourceBytes)))

		hex.Encode(source, sourceBytes)

		return createKey(source)
	},
}

func getKey(options ...keyOption) (*key, error) {
	keyfile := os.Getenv("GRAVE_KEYFILE")

	if keyfile == "" {
		keyfile = pathlib.Join(localDir, "key")
	}

	if source, err := ioutil.ReadFile(keyfile); err == nil {
		return createKey(source)
	}

	//          -- 80 chars --------------------------------------------------------------------
	userprintf("A key will be needed to decrypt the repository when it's fetched.  The key will\n")
	userprintf("be stored so that future fetches and pushes do not require you to see this\n")
	userprintf("menu again.\n")
	userprintf("Please select from one of the following options.\n")

	for i, option := range options {
		userprintf("%d) %s\n", i+1, option.description)
	}

	answer, err := prompt(fmt.Sprintf("Type a number 1-%d: ", len(options)))
	if err != nil {
		userprintf("%s\n", err)
		return nil, fmt.Errorf("invalid key option")
	}

	answerN, err := strconv.Atoi(answer)
	if err != nil {
		userprintf("%s\n", err)
		return nil, fmt.Errorf("invalid key option")
	} else if answerN <= 0 || answerN > len(options) {
		userprintf("Please choose a valid option.\n")
		return nil, fmt.Errorf("invalid key option")
	}

	key, err := options[answerN-1].procedure()
	if err != nil {
		userprintf("%s\n", err)
		return nil, fmt.Errorf("invalid key option")
	}

	return key, nil
}

func saveKey(key *key) error {
	filename := pathlib.Join(localDir, "key")
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	originalContents, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	if bytes.Equal(bytes.TrimSpace(originalContents), bytes.TrimSpace(key.source)) {
		return nil
	}

	if err := file.Truncate(0); err != nil {
		return err
	}

	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	if _, err := file.Write(key.source); err != nil {
		return err
	}

	userprintf("Key was saved to %s\n", filename)

	return nil
}

type errNotFound struct {
	url string
}

func (err *errNotFound) Error() string {
	return fmt.Sprintf("There is no repo at %s", err.url)
}

func authNewRequest(method string, urlstr string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, urlstr, body)
	if err != nil {
		return nil, err
	}

	u, err := neturl.Parse(urlstr)
	if err != nil {
		return nil, err
	}

	if u.User != nil {
		un := u.User.Username()
		pw, _ := u.User.Password()
		req.SetBasicAuth(un, pw)
	}

	return req, nil
}

func getDecryptedFile(path string, key *key) ([]byte, error) {
	if data, err := ioutil.ReadFile(path); os.IsNotExist(err) {
		return nil, &errNotFound{path}
	} else if err != nil {
		return nil, err
	} else {
		return decrypt(data, &key.key)
	}
}

func getDecryptedHTTP(url string, key *key) (data []byte, etag string, err error) {
	var cachedETagBytes []byte
	var res *http.Response

	cachedETagPath := pathlib.Join(localDir, "cached-etag")
	cachedDataPath := pathlib.Join(localDir, "cached-data")

	cachedETagBytes, err = ioutil.ReadFile(cachedETagPath)
	if err != nil && !os.IsNotExist(err) {
		return
	}

	cachedETag := string(cachedETagBytes)

	res, err = authorizedRequest(func(user *neturl.Userinfo) (*http.Request, error) {
		req, err := authNewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("If-None-Match", cachedETag)

		if user != nil {
			if pw, ok := user.Password(); ok {
				req.SetBasicAuth(user.Username(), pw)
			}
		}

		return req, nil
	})
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		err = &errNotFound{url}
		return
	} else if res.StatusCode == http.StatusNotModified {
		userprintf("304 Not Modified; using cached data.\n")

		data, err = ioutil.ReadFile(cachedDataPath)
		if err != nil {
			return
		}

		etag = cachedETag

		return
	} else if res.StatusCode != http.StatusOK {
		err = &errHTTPStatus{res, url}
		return
	}

	var encrypted []byte

	encrypted, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	data, err = decrypt(encrypted, &key.key)
	if err != nil {
		return
	}

	if err = ioutil.WriteFile(cachedDataPath, data, 0666); err != nil {
		return
	}

	etag = res.Header.Get("ETag")

	if err = ioutil.WriteFile(cachedETagPath, []byte(etag), 0666); err != nil {
		return
	}

	return
}

func getDecryptedData(url string, key *key) ([]byte, string, error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, "", err
	}

	switch parsedURL.Scheme {
	case "", "file":
		data, err := getDecryptedFile(parsedURL.Path, key)
		return data, "", err
	case "http", "https":
		return getDecryptedHTTP(url, key)
	default:
		return nil, "", fmt.Errorf("Unsupported URL scheme %#v", parsedURL.Scheme)
	}
}

type errHTTPStatus struct {
	res *http.Response
	url string
}

func (e *errHTTPStatus) Error() string {
	return fmt.Sprintf("%s: %s", e.url, http.StatusText(e.res.StatusCode))
}

type commandErr struct {
	bin  string
	args []string
	err  error
}

func (e *commandErr) Error() string {
	if len(e.args) > 0 {
		return fmt.Sprintf("%s %s: %s", e.bin, strings.Join(e.args, " "), e.err)
	}

	return fmt.Sprintf("%s: %s", e.bin, e.err)
}

func execCommand(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &commandErr{bin, args, err}
	}

	return nil
}

func emptyFetch(url string, key *key) (*fetchResult, error) {
	tempdir, err := ioutil.TempDir(localDir, "grave-temp-repo-")
	if err != nil {
		return nil, &suberr{"ioutil.TempDir", err}
	}

	if err := execCommand("git", "init", tempdir); err != nil {
		return nil, err
	}

	if err := os.Setenv("GIT_DIR", tempdir+"/.git"); err != nil {
		return nil, &suberr{"Setenv", err}
	}

	return &fetchResult{
		initial: true,
		tempDir: tempdir,
		key:     key,
	}, nil
}

type suberr struct {
	context string
	err     error
}

func (e *suberr) Error() string {
	return e.context + ": " + e.err.Error()
}

func push(fetched *fetchResult, url string) error {
	gitEmpty, err := Asset("empty.git.tar")
	if err != nil {
		return err
	}

	compressedArchive := bytes.NewBuffer(nil)
	hasher := sha256.New()

	if fetched.initial {
		userprintf("Running git repack -a -d -f...\n")
		if err := exec.Command("git", "repack", "-a", "-d", "-f").Run(); err != nil {
			return &suberr{"git repack -a -d -f", err}
		}
	} else {
		userprintf("Running git repack...\n")
		if err := exec.Command("git", "repack").Run(); err != nil {
			return &suberr{"git repack", err}
		}
	}

	userprintf("Running git gc...\n")
	if err := exec.Command("git", "gc").Run(); err != nil {
		return &suberr{"git gc", err}
	}

	packer := tarpack.Pack(fetched.tempDir, ".git")
	defer packer.Close()
	compressor, err := flate.NewWriterDict(io.MultiWriter(compressedArchive, hasher), flate.BestCompression, gitEmpty)
	if err != nil {
		return err
	}

	userprintf("Packing and compressing...\n")
	if _, err := io.Copy(compressor, packer); err != nil {
		return err
	}

	if err := compressor.Close(); err != nil {
		return err
	}

	newHash := make([]byte, 0, hasher.Size())
	newHash = hasher.Sum(newHash)

	if bytes.Equal(newHash, fetched.unencryptedHash) {
		userprintf("No need to push.\n")
		return nil
	}

	if fetched.key == nil {
		key, err := getKey(existingFileOption, typedInStringOption, generateNewKeyOption)
		if err != nil {
			return err
		}

		fetched.key = key
	}

	if err := saveKey(fetched.key); err != nil {
		return err
	}

	userprintf("Encrypting...\n")
	encryptedArchive, err := encrypt(compressedArchive.Bytes(), &fetched.key.key)
	if err != nil {
		return err
	}

	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return err
	}

	userprintf("Pushing...\n")

	switch parsedURL.Scheme {
	case "", "file":
		// Should files check the hash too to avoid overwrites?  If so, I think a
		// lock should be used.  That could've been accomplished, though, by
		// holding on to the file handle from the original fetch.
		return ioutil.WriteFile(url, encryptedArchive, 0644)
	case "http", "https":
		reqGenerator := func(user *neturl.Userinfo) (*http.Request, error) {
			req, err := authNewRequest("PUT", url, bytes.NewReader(encryptedArchive))
			if err != nil {
				return nil, err
			}

			if user != nil {
				pw, _ := user.Password()
				req.SetBasicAuth(user.Username(), pw)
			}

			if fetched.eTag == "" {
				req.Header.Set("If-Match", "nil")
			} else {
				req.Header.Set("If-Match", fetched.eTag)
			}

			req.ContentLength = int64(len(encryptedArchive))

			return req, nil
		}

		res, err := authorizedRequest(reqGenerator)
		if err != nil {
			return err
		} else if res.StatusCode == http.StatusConflict {
			return errConflict
		} else if res.StatusCode != http.StatusOK {
			return &errHTTPStatus{res, url}
		}

		return nil
	default:
		return fmt.Errorf("Unsupported URL: %s", url)
	}
}

func addURLUser(url string, user *neturl.Userinfo) (string, error) {
	parsed, err := neturl.Parse(url)
	if err != nil {
		return url, err
	}

	parsed.User = user

	return parsed.String(), nil
}

func fetch(url string) (*fetchResult, error) {
	emptyGit, err := Asset("empty.git.tar")
	if err != nil {
		return nil, err
	}

	key, err := getKey(existingFileOption, typedInStringOption)
	if err != nil {
		return nil, &suberr{"GetKey", err}
	}

	decryptedArchive, etag, err := getDecryptedData(url, key)
	if _, ok := err.(*errNotFound); ok {
		return emptyFetch(url, key)
	} else if err != nil {
		return nil, &suberr{"GetReader", err}
	}

	if err := saveKey(key); err != nil {
		return nil, err
	}

	hasher := sha256.New()

	if _, err := hasher.Write(decryptedArchive); err != nil {
		return nil, err
	}

	unencryptedHash := make([]byte, hasher.Size())
	unencryptedHash = hasher.Sum(unencryptedHash)

	decompressor := flate.NewReaderDict(bytes.NewReader(decryptedArchive), emptyGit)
	defer decompressor.Close()

	unarchiver := tar.NewReader(decompressor)

	tempdir, err := ioutil.TempDir("", "grave-temp-repo-")
	if err != nil {
		return nil, &suberr{"ioutil.TempDir", err}
	}

	if err := tarpack.Unpack(tempdir, unarchiver); err != nil {
		os.RemoveAll(tempdir)
		return nil, &suberr{"Unpack", err}
	}

	if err := os.Setenv("GIT_DIR", tempdir+"/.git"); err != nil {
		os.RemoveAll(tempdir)
		return nil, &suberr{"Setenv", err}
	}

	return &fetchResult{
		tempDir:         tempdir,
		eTag:            etag,
		key:             key,
		unencryptedHash: unencryptedHash,
	}, nil
}

func eval(bin string, args ...string) ([]byte, []byte, error) {
	outbuf := bytes.NewBuffer(nil)
	errbuf := bytes.NewBuffer(nil)

	cmd := exec.Command(bin, args...)
	cmd.Stdout = outbuf
	cmd.Stderr = errbuf

	err := cmd.Run()

	return outbuf.Bytes(), errbuf.Bytes(), err
}

type ref struct {
	objectname string
	refname    string
}

func gitShowRef() ([]ref, error) {
	piper, pipew := io.Pipe()

	defer piper.Close()
	defer pipew.Close()

	cmd := exec.Command("git", "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads/")
	cmd.Stdout = pipew

	errchan := make(chan error)
	donechan := make(chan bool)
	linechan := make(chan string)

	go func() {
		if err := cmd.Run(); err != nil {
			errchan <- err
		} else {
			donechan <- true
		}
	}()

	go func() {
		bufreader := bufio.NewReader(piper)

		for {
			line, err := bufreader.ReadString('\n')
			if err != nil {
				errchan <- err
				return
			}
			linechan <- strings.TrimSpace(line)
		}
	}()

	results := make([]ref, 0)

	for {
		select {
		case line := <-linechan:
			space := strings.Index(line, " ")
			if space == -1 {
				continue
			}
			results = append(results, ref{
				objectname: line[0:space],
				refname:    line[space+1:],
			})
		case err := <-errchan:
			return nil, err
		case <-donechan:
			return results, nil
		}
	}
}

func createExcl(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

// If the file exists, do nothing; otherwise, create it and make it empty.
func touch(path string) error {
	file, err := createExcl(path, 0666)
	if os.IsExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	return file.Close()
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func run() (reterr error) {
	if len(os.Args) < 3 {
		return fmt.Errorf("Usage: %s <remote-name> <url>", os.Args[0])
	}

	remoteName := os.Args[1]
	url := os.Args[2]
	stdinReader := bufio.NewReader(os.Stdin)

	var err error
	tty, err = os.Create("/dev/tty")
	if err != nil {
		return err
	}

	ttyReader = bufio.NewReader(tty)

	localDir = pathlib.Join(os.Getenv("GIT_DIR"), "grave", remoteName)

	if err := os.MkdirAll(localDir, 0755); err != nil {
		return err
	}

	gitmarks := pathlib.Join(localDir, "git.marks")
	gravemarks := pathlib.Join(localDir, "grave.marks")

	if err := touch(gitmarks); err != nil {
		return err
	}

	if err := touch(gravemarks); err != nil {
		return err
	}

	originalGitmarks, err := ioutil.ReadFile(gitmarks)
	if err != nil {
		return err
	}

	originalGravemarks, err := ioutil.ReadFile(gravemarks)
	if err != nil {
		return err
	}

	defer func() {
		if reterr != nil {
			ioutil.WriteFile(gitmarks, originalGitmarks, 0666)
			ioutil.WriteFile(gravemarks, originalGravemarks, 0666)
		}
	}()

	refspec := fmt.Sprintf("refs/heads/*:refs/grave/%s/*", remoteName)

	var fetched *fetchResult
	defer func() {
		if fetched != nil {
			os.RemoveAll(fetched.tempDir)
		}
	}()

	for {
		command, err := stdinReader.ReadString('\n')
		if err != nil {
			return err
		}

		if command == "capabilities\n" {
			// Other capabilities to consider: signed-tags, no-private-update, option
			fmt.Printf("import\n")
			fmt.Printf("export\n")
			fmt.Printf("refspec %s\n", refspec)
			fmt.Printf("*import-marks %s\n", gitmarks)
			fmt.Printf("*export-marks %s\n", gitmarks)
			fmt.Printf("\n")
		} else if command == "list\n" {
			if fetched == nil {
				fetched, err = fetch(url)
				if err != nil {
					return err
				}
			}

			refs, err := gitShowRef()
			if err != nil {
				return err
			}

			for _, ref := range refs {
				fmt.Printf("%s %s\n", ref.objectname, ref.refname)
			}

			head, _, err := eval("git", "symbolic-ref", "HEAD")
			if err != nil {
				return err
			}

			fmt.Printf("@%s HEAD\n", bytes.TrimSpace(head))
			fmt.Printf("\n")
		} else if strings.HasPrefix(command, "import ") {
			refs := make([]string, 0)

			for {
				ref := strings.TrimSpace(strings.TrimPrefix(command, "import "))

				refs = append(refs, ref)

				command, err = stdinReader.ReadString('\n')
				if err != nil {
					return err
				}

				if command == "\n" {
					break
				} else if !strings.HasPrefix(command, "import ") {
					return fmt.Errorf("Received a command in an import batch that did not start with 'import'")
				}
			}

			fmt.Printf("feature import-marks=%s\n", gitmarks)
			fmt.Printf("feature export-marks=%s\n", gitmarks)

			fmt.Printf("feature done\n")

			args := []string{"fast-export",
				"--import-marks", gravemarks,
				"--export-marks", gravemarks,
				"--refspec", refspec}
			args = append(args, refs...)

			cmd := exec.Command("git", args...)
			cmd.Stderr = os.Stderr
			cmd.Stdout = os.Stdout

			if err := cmd.Run(); err != nil {
				return err
			}

			fmt.Printf("done\n")
		} else if command == "export\n" {
			if fetched == nil {
				fetched, err = fetch(url)
				if err != nil {
					return err
				}
			}

			beforeRefs, err := gitShowRef()
			if err != nil {
				return err
			}

			beforeRefSet := make(map[ref]bool)

			for _, ref := range beforeRefs {
				beforeRefSet[ref] = true
			}

			userprintf("Running git fast-import...\n")
			cmd := exec.Command("git", "fast-import", "--quiet",
				"--import-marks="+gravemarks,
				"--export-marks="+gravemarks)

			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			if err := cmd.Run(); err != nil {
				return err
			}

			afterRefs, err := gitShowRef()
			if err != nil {
				return err
			}

			if err := push(fetched, url); err != nil {
				return err
			}

			for _, ref := range afterRefs {
				if !beforeRefSet[ref] {
					fmt.Printf("ok %s %s\n", ref.refname, ref.objectname)
				}
			}

			fmt.Printf("\n")
		} else if command == "\n" {
			break
		} else {
			return fmt.Errorf("Unknown command: %s", command)
		}
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
