/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package utils

import (
	"GADS/provider/logger"
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func ListFilesInZip(zipData []byte) ([]string, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	var fileNames []string
	for _, f := range r.File {
		fileNames = append(fileNames, f.Name)
	}
	return fileNames, nil
}

func UnzipInMemory(zipData []byte, dest string) error {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return err
	}

	firstFile := r.File[0]
	if !firstFile.FileInfo().IsDir() {
		fmt.Printf("Unzipping %s:\n", firstFile.Name)
		rc, err := firstFile.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		// define the new file path
		newFilePath := fmt.Sprintf("%s/%s", dest, firstFile.Name)

		uncompressedFile, err := os.Create(newFilePath)
		if err != nil {
			return err
		}
		_, err = io.Copy(uncompressedFile, rc)
		if err != nil {
			return err
		}
	} else {
		for _, f := range r.File {
			logger.ProviderLogger.LogDebug("unzip_app", fmt.Sprintf("Unzipping %s:\n", f.Name))
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			// define the new file path
			newFilePath := fmt.Sprintf("%s/%s", dest, f.Name)

			// CASE 1 : we have a directory
			if f.FileInfo().IsDir() {
				// if we have a directory we have to create it
				err = os.MkdirAll(newFilePath, 0777)
				if err != nil {
					return err
				}
				// we can go to next iteration
				continue
			}

			// CASE 2 : we have a file
			// create new uncompressed file
			uncompressedFile, err := os.Create(newFilePath)
			if err != nil {
				return err
			}
			_, err = io.Copy(uncompressedFile, rc)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func Unzip(src string, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	os.MkdirAll(dest, 0755)

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		fpath := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, f.Mode())
		} else {
			outFile, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer outFile.Close()
			if _, err := io.Copy(outFile, rc); err != nil {
				return err
			}
		}
	}
	return nil
}
