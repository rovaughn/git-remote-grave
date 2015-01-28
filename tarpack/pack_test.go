package tarpack

import (
	"archive/tar"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"testing"
)

type TestEntry struct {
	Name string
	Type string
	Body []byte
}

func MakeEntries(root string, entries []string) ([]TestEntry, error) {
	result := make([]TestEntry, 0, len(entries))

	sort.Sort(sort.StringSlice(entries))

	for _, entry := range entries {
		file, err := os.Open(path.Join(root, entry))
		if err != nil {
			return result, err
		}
		defer file.Close()

		finfo, err := file.Stat()
		if err != nil {
			return result, err
		}

		if finfo.IsDir() {
			result = append(result, TestEntry{
				Name: entry,
				Type: "dir",
			})

			subentries, err := file.Readdirnames(0)
			if err != nil {
				return result, err
			}

			for i := range subentries {
				subentries[i] = path.Join(entry, subentries[i])
			}

			subresult, err := MakeEntries(root, subentries)
			if err != nil {
				return result, err
			}

			result = append(result, subresult...)
		} else if finfo.Mode().IsRegular() {
			body, err := ioutil.ReadAll(file)
			if err != nil {
				return result, err
			}

			result = append(result, TestEntry{
				Name: entry,
				Type: "file",
				Body: body,
			})
		}
	}

	return result, nil
}

func TestPacker(t *testing.T) {
	testEntries, err := MakeEntries(".", []string{"pack-test"})
	if err != nil {
		t.Fatal(err)
	}

	packer := NewPacker(".", "pack-test")
	reader := tar.NewReader(packer)

	for _, testEntry := range testEntries {
		header, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}

		body, err := ioutil.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}

		if header.Name != testEntry.Name {
			t.Errorf("Expected name to be %s, not %s", testEntry.Name, header.Name)
		}

		if header.Size != int64(len(body)) {
			t.Errorf("Header has size %d, but body has size %d", header.Size, len(body))
		}

		if !bytes.Equal(testEntry.Body, body) {
			t.Errorf("Expected body to be %s, not %s", testEntry.Body, body)
		}
	}

	if _, err := reader.Next(); err == nil {
		t.Error("There are more entries than expected.")
	} else if err != io.EOF {
		t.Fatal(err)
	}
}

func TestUnpack(t *testing.T) {
	testEntries, err := MakeEntries(".", []string{"pack-test"})
	if err != nil {
		t.Fatal(err)
	}

	target, err := ioutil.TempDir("", "unpack")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(target); err != nil {
			t.Fatal(err)
		}
	}()

	packer := NewPacker(".", "pack-test")
	reader := tar.NewReader(packer)

	if err := Unpack(target, reader); err != nil {
		t.Fatal(err)
	}

	for _, testEntry := range testEntries {
		if testEntry.Type == "file" {
			body, err := ioutil.ReadFile(path.Join(target, testEntry.Name))
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(body, testEntry.Body) {
				t.Errorf("Expected file %s to have body %s, but it had %s", testEntry.Name, testEntry.Body, body)
			}
		}
	}
}
