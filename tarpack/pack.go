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
	zeroTime = time.Unix(0, 0)
)

func verifyName(name string) error {
	components := strings.Split(filepath.ToSlash(filepath.Clean(name)), "/")

	for _, component := range components {
		if component == ".." {
			return fmt.Errorf("%s refers to a parent directory", name)
		}
	}

	return nil
}

// Unpack unpacks a tar.Reader into the given root directory.
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
			return fmt.Errorf("%s is not a regular file or directory", header.Name)
		}
	}
}

func pack(archiver *tar.Writer, root string, entries []string) error {
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
		header.ModTime = zeroTime
		header.Uid = 0
		header.Gid = 0
		header.Uname = ""
		header.Gname = ""
		header.AccessTime = zeroTime
		header.ChangeTime = zeroTime

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

			if err := pack(archiver, root, subentries); err != nil {
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

// Pack returns a reader that produces bytes of a tar archive produced by
// packing the entries under root.  The names are always sorted.
func Pack(root string, entries ...string) io.ReadCloser {
	reader, writer := io.Pipe()

	go func() {
		archiver := tar.NewWriter(writer)

		packErr := pack(archiver, root, entries)
		archiverErr := archiver.Close()

		if packErr != nil {
			writer.CloseWithError(packErr)
		} else if archiverErr != nil {
			writer.CloseWithError(archiverErr)
		} else {
			writer.Close()
		}
	}()

	return reader
}
