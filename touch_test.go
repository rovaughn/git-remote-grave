package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestTouch(t *testing.T) {
	file, err := ioutil.TempFile("/tmp", "test-touch-")
	if err != nil {
		t.Fatal(err)
	}
	filename := file.Name()
	defer file.Close()
	defer os.Remove(filename)

	if _, err := file.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	if err := Touch(filename); err != nil {
		t.Fatal(err)
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, []byte("hello")) {
		t.Error("The contents of the temporary file were modified after being touched; they were %#v", data)
	}

	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}

	if err := Touch(filename); err != nil {
		t.Fatal(err)
	}

	data, err = ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, nil) {
		t.Errorf("The contents of the touched file were not empty; got %#v", data)
	}
}
