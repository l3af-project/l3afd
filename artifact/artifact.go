package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/l3af-project/l3afd/v2/models"
)

var (
	copyBufPool sync.Pool = sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}
)

func DownloadArtifact(urlpath string, timeout time.Duration, buf *bytes.Buffer) error {
	URL, err := ValidateURL(urlpath)
	if err != nil {
		return err
	}
	switch URL.Scheme {
	case models.HttpScheme, models.HttpsScheme:
		{
			timeOut := time.Duration(timeout) * time.Second
			var netTransport = &http.Transport{
				ResponseHeaderTimeout: timeOut,
			}
			client := http.Client{Transport: netTransport, Timeout: timeOut}
			// Get the data
			resp, err := client.Get(URL.String())
			if err != nil {
				return fmt.Errorf("download failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("get request returned unexpected status code: %d (%s), %d was expected\n\tResponse Body: %s", resp.StatusCode, http.StatusText(resp.StatusCode), http.StatusOK, buf.Bytes())
			}
			buf.ReadFrom(resp.Body)
			return nil
		}
	case models.FileScheme:
		{
			if FileExists(URL.Path) {
				f, err := os.Open(URL.Path)
				if err != nil {
					return fmt.Errorf("opening err : %w", err)
				}
				buf.ReadFrom(f)
				f.Close()
			} else {
				return fmt.Errorf("artifact is not found")
			}
			return nil
		}
	default:
		return fmt.Errorf("unknown url scheme")
	}
}
func ExtractArtifact(artifactName string, buf *bytes.Buffer, tempDir string) error {
	switch artifact := artifactName; {
	case strings.HasSuffix(artifact, ".zip"):
		{
			c := bytes.NewReader(buf.Bytes())
			zipReader, err := zip.NewReader(c, int64(c.Len()))
			if err != nil {
				return fmt.Errorf("failed to create zip reader: %w", err)
			}
			for _, file := range zipReader.File {

				zippedFile, err := file.Open()
				if err != nil {
					return fmt.Errorf("unzip failed: %w", err)
				}
				defer zippedFile.Close()

				extractedFilePath, err := ValidatePath(file.Name, tempDir)
				if err != nil {
					return err
				}

				if file.FileInfo().IsDir() {
					os.MkdirAll(extractedFilePath, file.Mode())
				} else {
					outputFile, err := os.OpenFile(
						extractedFilePath,
						os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
						file.Mode(),
					)
					if err != nil {
						return fmt.Errorf("unzip failed to create file: %w", err)
					}
					defer outputFile.Close()

					buf := copyBufPool.Get().(*bytes.Buffer)
					_, err = io.CopyBuffer(outputFile, zippedFile, buf.Bytes())
					if err != nil {
						return fmt.Errorf("GetArtifacts failed to copy files: %w", err)
					}
					copyBufPool.Put(buf)
				}
			}
			return nil
		}
	case strings.HasSuffix(artifact, ".tar.gz"):
		{
			archive, err := gzip.NewReader(buf)
			if err != nil {
				return fmt.Errorf("failed to create Gzip reader: %w", err)
			}
			defer archive.Close()
			tarReader := tar.NewReader(archive)

			for {
				header, err := tarReader.Next()

				if err == io.EOF {
					break
				} else if err != nil {
					return fmt.Errorf("untar failed: %w", err)
				}

				fPath, err := ValidatePath(header.Name, tempDir)
				if err != nil {
					return err
				}

				info := header.FileInfo()
				if info.IsDir() {
					if err = os.MkdirAll(fPath, info.Mode()); err != nil {
						return fmt.Errorf("untar failed to create directories: %w", err)
					}
					continue
				}

				file, err := os.OpenFile(fPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
				if err != nil {
					return fmt.Errorf("untar failed to create file: %w", err)
				}
				defer file.Close()

				buf := copyBufPool.Get().(*bytes.Buffer)
				_, err = io.CopyBuffer(file, tarReader, buf.Bytes())
				if err != nil {
					return fmt.Errorf("GetArtifacts failed to copy files: %w", err)
				}
				copyBufPool.Put(buf)
			}
			return nil
		}
	default:
		return fmt.Errorf("unknown artifact format")
	}
}

func ValidateURL(urlpath string) (*url.URL, error) {
	URL, err := url.Parse(urlpath)
	if err != nil {
		return nil, fmt.Errorf("unknown url format : %w", err)
	}
	if URL.Scheme == "" {
		return nil, fmt.Errorf("URL scheme is missing")
	}
	if URL.Scheme == models.HttpScheme || URL.Scheme == models.HttpsScheme {
		if URL.Host == "" {
			return nil, fmt.Errorf("URL host is missing")
		}
		// Forbid fragment in the URL to prevent potential attacks
		if URL.Fragment != "" {
			return nil, fmt.Errorf("URL must not contain a fragment")
		}
	}
	if strings.Contains(URL.Path, "..") {
		return nil, fmt.Errorf("URL path must not contain '..'")
	}
	return URL, nil
}

func ValidatePath(filePath string, destination string) (string, error) {
	destpath := filepath.Join(destination, filePath)
	if strings.Contains(filePath, "..") {
		return "", fmt.Errorf(" file contains filepath (%s) that includes (..)", filePath)
	}
	if !strings.HasPrefix(destpath, filepath.Clean(destination)+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s: illegal file path", filePath)
	}
	return destpath, nil
}

// fileExists checks if a file exists or not
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
