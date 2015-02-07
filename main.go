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
	"github.com/alecrn/git-remote-grave/tarpack"
	"github.com/gcmurphy/getpass"
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

func Userprintf(format string, a ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, format, a...); err != nil {
		panic(err)
	}
}

func Debugf(format string, a ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, format, a...); err != nil {
		panic(err)
	}
}

var (
	TTY       *os.File
	TTYReader *bufio.Reader
	LocalDir  string
)

func Prompt(message string) (string, error) {
	var err error

	Userprintf("%s", message)

	line, err := TTYReader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

func PromptSecret(message string) (response string, err error) {
	return getpass.GetPassWithOptions(message, 0, 64)
}

type FetchResult struct {
	Initial         bool
	TempDir         string
	ETag            string
	Key             *Key
	URL             string
	User            *neturl.Userinfo
	UnencryptedHash []byte
}

func AuthorizedRequest(reqGenerator func() (*http.Request, error)) (*http.Response, *neturl.Userinfo, error) {
	client := &http.Client{}

	req, err := reqGenerator()
	if err != nil {
		return nil, nil, err
	}

	username, password, _ := req.BasicAuth()

	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	if res.StatusCode == http.StatusForbidden {
		res.Body.Close()

		if username != "" && password != "" {
			return nil, nil, fmt.Errorf("Forbidden")
		}

		Userprintf("The server responded with %d Forbidden.\n", res.StatusCode)

		if username == "" {
			username, err = Prompt("Username: ")
			if err != nil {
				return nil, nil, err
			}
		}

		if password == "" {
			password, err = PromptSecret("Password: ")
			if err != nil {
				return nil, nil, err
			}
		}

		req, err = reqGenerator()
		if err != nil {
			return nil, nil, err
		}

		req.SetBasicAuth(username, password)

		res, err = client.Do(req)
		if err != nil {
			return nil, nil, err
		}

		if res.StatusCode == http.StatusForbidden {
			Userprintf("The server responded with %d Forbidden.\n", res.StatusCode)

			return nil, nil, fmt.Errorf("Forbidden")
		} else {
			return res, neturl.UserPassword(username, password), nil
		}
	} else {
		return res, neturl.UserPassword(username, password), nil
	}
}

type Key struct {
	Source []byte
	Key    [32]byte
}

func CreateKey(source []byte) (*Key, error) {
	trimmedSource := bytes.TrimSpace(source)

	hasher := sha256.New()

	if _, err := hasher.Write(trimmedSource); err != nil {
		return nil, err
	}

	key := &Key{
		Source: source,
	}

	hasher.Sum(key.Key[0:0:32])

	return key, nil
}

type KeyOption struct {
	Description string
	Procedure   func() (*Key, error)
}

var ExistingFileOption KeyOption = KeyOption{
	Description: "Use the contents of an existing file.",
	Procedure: func() (*Key, error) {
		filename, err := Prompt("Filename (contents can be of any length): ")
		if err != nil {
			return nil, err
		}

		source, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		return CreateKey(source)
	},
}

var TypedInStringOption KeyOption = KeyOption{
	Description: "Use a typed-in string.",
	Procedure: func() (*Key, error) {
		Userprintf("Type a string of any length up to 64 characters.\n")
		source, err := PromptSecret("Key source: ")
		if err != nil {
			return nil, err
		}

		return CreateKey([]byte(source))
	},
}

var GenerateNewKeyOption KeyOption = KeyOption{
	Description: "Randomly generate a new key.",
	Procedure: func() (*Key, error) {
		sourceBytes := make([]byte, 32)

		if _, err := rand.Read(sourceBytes); err != nil {
			return nil, err
		}

		source := make([]byte, hex.EncodedLen(len(sourceBytes)))

		hex.Encode(source, sourceBytes)

		return CreateKey(source)
	},
}

func GetKey(options ...KeyOption) (*Key, error) {
	keyfile := os.Getenv("GRAVE_KEYFILE")

	if keyfile == "" {
		keyfile = pathlib.Join(LocalDir, "key")
	}

	if source, err := ioutil.ReadFile(keyfile); err == nil {
		return CreateKey(source)
	}

	//          -- 80 chars --------------------------------------------------------------------
	Userprintf("A key will be needed to decrypt the repository when it's fetched.  The key will\n")
	Userprintf("be stored so that future fetches and pushes do not require you to see this\n")
	Userprintf("menu again.\n")
	Userprintf("Please select from one of the following options.\n")

	for i, option := range options {
		Userprintf("%d) %s\n", i+1, option.Description)
	}

	answer, err := Prompt(fmt.Sprintf("Type a number 1-%d: ", len(options)))
	if err != nil {
		Userprintf("%s\n", err)
		return nil, fmt.Errorf("Invalid key option.")
	}

	answerN, err := strconv.Atoi(answer)
	if err != nil {
		Userprintf("%s\n", err)
		return nil, fmt.Errorf("Invalid key option.")
	} else if answerN <= 0 || answerN > len(options) {
		Userprintf("Please choose a valid option.\n")
		return nil, fmt.Errorf("Invalid key option")
	}

	if key, err := options[answerN-1].Procedure(); err != nil {
		Userprintf("%s\n", err)
		return nil, fmt.Errorf("Invalid key option")
	} else {
		return key, nil
	}
}

func SaveKey(key *Key) error {
	filename := pathlib.Join(LocalDir, "key")
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	originalContents, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	if bytes.Equal(bytes.TrimSpace(originalContents), bytes.TrimSpace(key.Source)) {
		return nil
	}

	if err := file.Truncate(0); err != nil {
		return err
	}

	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	if _, err := file.Write(key.Source); err != nil {
		return err
	}

	Userprintf("Key was saved to %s\n", filename)

	return nil
}

type ErrNotFound struct {
	URL string
}

func (err *ErrNotFound) Error() string {
	return fmt.Sprintf("There is no repo at %s", err.URL)
}

func AuthNewRequest(method string, urlstr string, body io.Reader) (*http.Request, error) {
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

func GetDecryptedFile(path string, key *Key) ([]byte, error) {
	if data, err := ioutil.ReadFile(path); os.IsNotExist(err) {
		return nil, &ErrNotFound{path}
	} else if err != nil {
		return nil, err
	} else {
		return Decrypt(data, &key.Key)
	}
}

func GetDecryptedHTTP(url string, key *Key) (data []byte, etag string, user *neturl.Userinfo, err error) {
	var cachedETagBytes []byte
	var res *http.Response

	cachedETagPath := pathlib.Join(LocalDir, "cached-etag")
	cachedDataPath := pathlib.Join(LocalDir, "cached-data")

	cachedETagBytes, err = ioutil.ReadFile(cachedETagPath)
	if err != nil && !os.IsNotExist(err) {
		return
	}

	cachedETag := string(cachedETagBytes)

	res, user, err = AuthorizedRequest(func() (*http.Request, error) {
		req, err := AuthNewRequest("GET", url, nil)
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
		err = &ErrNotFound{url}
		return
	} else if res.StatusCode == http.StatusNotModified {
		Userprintf("304 Not Modified; using cached data.\n")

		data, err = ioutil.ReadFile(cachedDataPath)
		if err != nil {
			return
		}

		etag = cachedETag

		return
	} else if res.StatusCode != http.StatusOK {
		err = &ErrHTTPStatus{res, url}
		return
	}

	var encrypted []byte

	encrypted, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	data, err = Decrypt(encrypted, &key.Key)
	if err != nil {
		return
	}

	if err = ioutil.WriteFile(cachedDataPath, data, 0666); err != nil {
		return
	}

	if err = ioutil.WriteFile(cachedETagPath, []byte(res.Header.Get("ETag")), 0666); err != nil {
		return
	}

	return
}

func GetDecryptedData(url string, key *Key) ([]byte, string, *neturl.Userinfo, error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, "", nil, err
	}

	switch parsedURL.Scheme {
	case "", "file":
		data, err := GetDecryptedFile(parsedURL.Path, key)
		return data, "", nil, err
	case "http", "https":
		return GetDecryptedHTTP(url, key)
	default:
		return nil, "", nil, fmt.Errorf("Unsupported URL scheme %#v", parsedURL.Scheme)
	}
}

type ErrHTTPStatus struct {
	Res *http.Response
	URL string
}

func (e *ErrHTTPStatus) Error() string {
	return fmt.Sprintf("%s: %s", e.URL, http.StatusText(e.Res.StatusCode))
}

type CommandErr struct {
	Bin  string
	Args []string
	Err  error
}

func (e *CommandErr) Error() string {
	if len(e.Args) > 0 {
		return e.Bin + " " + strings.Join(e.Args, " ") + ": " + e.Err.Error()
	} else {
		return e.Bin + ": " + e.Err.Error()
	}
}

func Exec(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &CommandErr{bin, args, err}
	} else {
		return nil
	}
}

func EmptyFetch(url string, key *Key) (*FetchResult, error) {
	tempdir, err := ioutil.TempDir(LocalDir, "grave-temp-repo-")
	if err != nil {
		return nil, &Suberr{"ioutil.TempDir", err}
	}

	if err := Exec("git", "init", tempdir); err != nil {
		return nil, err
	}

	if err := os.Setenv("GIT_DIR", tempdir+"/.git"); err != nil {
		return nil, &Suberr{"Setenv", err}
	}

	return &FetchResult{
		Initial: true,
		TempDir: tempdir,
		URL:     url,
		Key:     key,
	}, nil
}

type Suberr struct {
	Context string
	Err     error
}

func (e *Suberr) Error() string {
	return e.Context + ": " + e.Err.Error()
}

func Push(fetched *FetchResult, url string) error {
	gitEmpty, err := Asset("empty.git")
	if err != nil {
		return err
	}

	compressedArchive := bytes.NewBuffer(nil)
	hasher := sha256.New()

	if fetched.Initial {
		Userprintf("Running git repack -a -d -f...\n")
		if err := exec.Command("git", "repack", "-a", "-d", "-f").Run(); err != nil {
			return &Suberr{"git repack -a -d -f", err}
		}
	} else {
		Userprintf("Running git repack...\n")
		if err := exec.Command("git", "repack").Run(); err != nil {
			return &Suberr{"git repack", err}
		}
	}

	Userprintf("Running git gc...\n")
	if err := exec.Command("git", "gc").Run(); err != nil {
		return &Suberr{"git gc", err}
	}

	packer := tarpack.NewPacker(fetched.TempDir, ".git")
	compressor, err := flate.NewWriterDict(io.MultiWriter(compressedArchive, hasher), flate.BestCompression, gitEmpty)
	if err != nil {
		return err
	}

	Userprintf("Packing and compressing...\n")
	if _, err := io.Copy(compressor, packer); err != nil {
		return err
	}

	if err := compressor.Close(); err != nil {
		return err
	}

	newHash := make([]byte, 0, hasher.Size())
	newHash = hasher.Sum(newHash)

	if bytes.Equal(newHash, fetched.UnencryptedHash) {
		Userprintf("No need to push.\n")
		return nil
	}

	if fetched.Key == nil {
		key, err := GetKey(ExistingFileOption, TypedInStringOption, GenerateNewKeyOption)
		if err != nil {
			return err
		}

		fetched.Key = key
	}

	if err := SaveKey(fetched.Key); err != nil {
		return err
	}

	Userprintf("Encrypting...\n")
	encryptedArchive, err := Encrypt(compressedArchive.Bytes(), &fetched.Key.Key)
	if err != nil {
		return err
	}

	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return err
	}

	Userprintf("Pushing...\n")

	switch parsedURL.Scheme {
	case "", "file":
		// Should files check the hash too to avoid overwrites?  If so, I think a
		// lock should be used.  That could've been accomplished, though, by
		// holding on to the file handle from the original fetch.
		return ioutil.WriteFile(url, encryptedArchive, 0644)
	case "http", "https":
		reqGenerator := func() (*http.Request, error) {
			req, err := AuthNewRequest("PUT", url, bytes.NewReader(encryptedArchive))
			if err != nil {
				return nil, err
			}

			if fetched.User != nil {
				pw, _ := fetched.User.Password()
				req.SetBasicAuth(fetched.User.Username(), pw)
			}

			if fetched.ETag == "" {
				req.Header.Set("If-Match", "nil")
			} else {
				req.Header.Set("If-Match", fetched.ETag)
			}

			req.ContentLength = int64(len(encryptedArchive))

			return req, nil
		}

		res, user, err := AuthorizedRequest(reqGenerator)
		if err != nil {
			return err
		} else if res.StatusCode == http.StatusConflict {
			return fmt.Errorf("The version of the repository that was fetched and the current version differ; most likely the server's archive was updated during the push.  Repeating the operations should fix it.")
		} else if res.StatusCode != http.StatusOK {
			return &ErrHTTPStatus{res, url}
		}

		fetched.User = user

		return nil
	default:
		return fmt.Errorf("Unsupported URL: %s", url)
	}
}

// TODO: Instead of passing around URLs as strings, passing them around as *net.URLs
//       would be better.
func GetRemoteHash(url string) ([]byte, *neturl.Userinfo, error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, nil, err
	}

	switch parsedURL.Scheme {
	case "http", "https":
		res, user, err := AuthorizedRequest(func() (*http.Request, error) {
			return AuthNewRequest("GET", url+"/hash", nil)
		})
		if err != nil {
			return nil, nil, err
		} else if res.StatusCode == http.StatusNotFound {
			res.Body.Close()
			return nil, nil, &ErrNotFound{url}
		} else if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return nil, nil, &ErrHTTPStatus{res, url}
		}
		defer res.Body.Close()

		hexhash, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, nil, err
		}

		hexhash = bytes.TrimSpace(hexhash)

		hash := make([]byte, hex.DecodedLen(len(hexhash)))

		if _, err := hex.Decode(hash, hexhash); err != nil {
			return nil, nil, err
		}

		return hash, user, nil
	default:
		return nil, nil, fmt.Errorf("Unsupported remote hash scheme: %s", parsedURL.Scheme)
	}
}

func AddURLUser(url string, user *neturl.Userinfo) (string, error) {
	parsed, err := neturl.Parse(url)
	if err != nil {
		return url, err
	}

	parsed.User = user

	return parsed.String(), nil
}

func Fetch(url string) (*FetchResult, error) {
	emptyGit, err := Asset("empty.git")
	if err != nil {
		return nil, err
	}

	key, err := GetKey(ExistingFileOption, TypedInStringOption)
	if err != nil {
		return nil, &Suberr{"GetKey", err}
	}

	decryptedArchive, etag, user, err := GetDecryptedData(url, key)
	if _, ok := err.(*ErrNotFound); ok {
		return EmptyFetch(url, key)
	} else if err != nil {
		return nil, &Suberr{"GetReader", err}
	}

	if err := SaveKey(key); err != nil {
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
		return nil, &Suberr{"ioutil.TempDir", err}
	}

	if err := tarpack.Unpack(tempdir, unarchiver); err != nil {
		os.RemoveAll(tempdir)
		return nil, &Suberr{"Unpack", err}
	}

	if err := os.Setenv("GIT_DIR", tempdir+"/.git"); err != nil {
		os.RemoveAll(tempdir)
		return nil, &Suberr{"Setenv", err}
	}

	return &FetchResult{
		TempDir:         tempdir,
		ETag:            etag,
		Key:             key,
		URL:             url,
		User:            user,
		UnencryptedHash: unencryptedHash,
	}, nil
}

func Eval(bin string, args ...string) ([]byte, []byte, error) {
	outbuf := bytes.NewBuffer(nil)
	errbuf := bytes.NewBuffer(nil)

	cmd := exec.Command(bin, args...)
	cmd.Stdout = outbuf
	cmd.Stderr = errbuf

	err := cmd.Run()

	return outbuf.Bytes(), errbuf.Bytes(), err
}

type Ref struct {
	Objectname string
	Refname    string
}

func GitShowRef() ([]Ref, error) {
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
			} else {
				linechan <- strings.TrimSpace(line)
			}
		}
	}()

	results := make([]Ref, 0)

	for {
		select {
		case line := <-linechan:
			space := strings.Index(line, " ")
			if space == -1 {
				continue
			}
			results = append(results, Ref{
				Objectname: line[0:space],
				Refname:    line[space+1:],
			})
		case err := <-errchan:
			return nil, err
		case <-donechan:
			return results, nil
		}
	}
}

func CreateExcl(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

// If the file exists, do nothing; otherwise, create it and make it empty.
func Touch(path string) error {
	file, err := CreateExcl(path, 0666)
	if os.IsExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	return file.Close()
}

func Main() (er error) {
	if len(os.Args) < 3 {
		return fmt.Errorf("Usage: %s <remote-name> <url>", os.Args[0])
	}

	remoteName := os.Args[1]
	url := os.Args[2]
	stdinReader := bufio.NewReader(os.Stdin)

	var err error
	TTY, err = os.Create("/dev/tty")
	if err != nil {
		return err
	}

	TTYReader = bufio.NewReader(TTY)

	LocalDir = pathlib.Join(os.Getenv("GIT_DIR"), "grave", remoteName)

	if err := os.MkdirAll(LocalDir, 0755); err != nil {
		return err
	}

	gitmarks := pathlib.Join(LocalDir, "git.marks")
	gravemarks := pathlib.Join(LocalDir, "grave.marks")

	if err := Touch(gitmarks); err != nil {
		return err
	}

	if err := Touch(gravemarks); err != nil {
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
		if er != nil {
			ioutil.WriteFile(gitmarks, originalGitmarks, 0666)
			ioutil.WriteFile(gravemarks, originalGravemarks, 0666)
		}
	}()

	refspec := fmt.Sprintf("refs/heads/*:refs/grave/%s/*", remoteName)

	var fetched *FetchResult
	defer func() {
		if fetched != nil {
			os.RemoveAll(fetched.TempDir)
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
				fetched, err = Fetch(url)
				if err != nil {
					return &Suberr{"list", &Suberr{"fetch", err}}
				}
			}

			refs, err := GitShowRef()
			if err != nil {
				return &Suberr{"list", &Suberr{"git show refs", err}}
			}

			for _, ref := range refs {
				fmt.Printf("%s %s\n", ref.Objectname, ref.Refname)
			}

			head, _, err := Eval("git", "symbolic-ref", "HEAD")
			if err != nil {
				return &Suberr{"list", &Suberr{"symbolic-ref", err}}
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
				return &Suberr{"git", &Suberr{"fast-export", err}}
			}

			fmt.Printf("done\n")
		} else if command == "export\n" {
			if fetched == nil {
				fetched, err = Fetch(url)
				if err != nil {
					return err
				}
			}

			beforeRefs, err := GitShowRef()
			if err != nil {
				return &Suberr{"collecting before refs", err}
			}

			beforeRefSet := make(map[Ref]bool)

			for _, ref := range beforeRefs {
				beforeRefSet[ref] = true
			}

			Userprintf("Running git fast-import...\n")
			cmd := exec.Command("git", "fast-import", "--quiet",
				"--import-marks="+gravemarks,
				"--export-marks="+gravemarks)

			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			if err := cmd.Run(); err != nil {
				return &Suberr{"git fast-import", err}
			}

			afterRefs, err := GitShowRef()
			if err != nil {
				return &Suberr{"collecting after refs", err}
			}

			if err := Push(fetched, url); err != nil {
				return err
			}

			for _, ref := range afterRefs {
				if !beforeRefSet[ref] {
					fmt.Printf("ok %s %s\n", ref.Refname, ref.Objectname)
				}
			}

			fmt.Printf("\n")
		} else if command == "\n" {
			return nil
		} else {
			return fmt.Errorf("Unknown command: %s", command)
		}
	}
}

func main() {
	if err := Main(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
