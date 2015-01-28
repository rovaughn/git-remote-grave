package tarpack

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	ZeroTime = time.Unix(0, 0)
)

func verifyName(name string) error {
	components := strings.Split(filepath.ToSlash(filepath.Clean(name)), "/")

	for _, component := range components {
		if component == ".." {
			return fmt.Errorf("%s contains ..", name)
		}
	}

	return nil
}

// Unpacks a tar.Reader into the given root directory.
func Unpack(root string, reader *tar.Reader) error {
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		finfo := header.FileInfo()
		name := header.Name

		if err := verifyName(name); err != nil {
			return err
		}

		if finfo.IsDir() {
			if err := os.MkdirAll(path.Join(root, header.Name), finfo.Mode()); err != nil {
				return err
			}
		} else if finfo.Mode().IsRegular() {
			file, err := os.Create(path.Join(root, header.Name))
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(file, reader); err != nil {
				return err
			}

			file.Close()
		} else {
			return fmt.Errorf("%s is not a regular file or directory.", header.Name)
		}
	}
}

type Packer struct {
	reader   io.Reader
	archiver *tar.Writer
}

func (p *Packer) Read(b []byte) (int, error) {
	n, err := p.reader.Read(b)
	return n, err
}

func Pack(archiver *tar.Writer, root string, entries []string) error {
	sort.Sort(sort.StringSlice(entries))

	for _, entry := range entries {
		file, err := os.Open(path.Join(root, entry))
		if err != nil {
			return err
		}
		defer file.Close()

		finfo, err := file.Stat()
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(finfo, "")
		if err != nil {
			return err
		}

		header.Name = entry
		header.ModTime = ZeroTime
		header.Uid = 0
		header.Gid = 0
		header.Uname = ""
		header.Gname = ""
		header.AccessTime = ZeroTime
		header.ChangeTime = ZeroTime

		if finfo.IsDir() {
			if err := archiver.WriteHeader(header); err != nil {
				return err
			}

			subentries, err := file.Readdirnames(0)
			if err != nil {
				return err
			}

			for j := range subentries {
				subentries[j] = path.Join(entry, subentries[j])
			}

			if err := Pack(archiver, root, subentries); err != nil {
				return err
			}
		} else if finfo.Mode().IsRegular() {
			if err := archiver.WriteHeader(header); err != nil {
				return err
			}

			if n, err := io.Copy(archiver, file); err != nil {
				return err
			} else if n != header.Size {
				return fmt.Errorf("The size of %s/%s changed from %d to %d bytes", root, entry, header.Size, n)
			}
		}

		file.Close()
	}

	return nil
}

// Returns a reader that produces bytes of a tar archive produced by packing
// the entries under root.  The names are always sorted.
func NewPacker(root string, entries ...string) *Packer {
	reader, writer := io.Pipe()

	archiver := tar.NewWriter(writer)

	packer := &Packer{
		reader:   reader,
		archiver: archiver,
	}

	go func() {
		//defer archiver.Close()

		packErr := Pack(archiver, root, entries)
		archiverErr := archiver.Close()

		if packErr != nil {
			writer.CloseWithError(packErr)
		} else if archiverErr != nil {
			writer.CloseWithError(archiverErr)
		} else {
			writer.Close()
		}
	}()

	return packer
}
