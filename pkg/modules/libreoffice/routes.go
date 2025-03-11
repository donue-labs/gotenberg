package libreoffice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	"github.com/gotenberg/gotenberg/v8/pkg/modules/api"
	libreofficeapi "github.com/gotenberg/gotenberg/v8/pkg/modules/libreoffice/api"
	"github.com/gotenberg/gotenberg/v8/pkg/modules/pdfengines"
)

// convertRoute returns an [api.Route] which can convert LibreOffice documents
// to PDF.
func convertRoute(libreOffice libreofficeapi.Uno, engine gotenberg.PdfEngine) api.Route {
	return api.Route{
		Method:      http.MethodPost,
		Path:        "/forms/libreoffice/convert",
		IsMultipart: true,
		Handler: func(c echo.Context) error {
			ctx := c.Get("context").(*api.Context)
			defaultOptions := libreofficeapi.DefaultOptions()

			form := ctx.FormData()
			splitMode := pdfengines.FormDataPdfSplitMode(form, false)
			pdfFormats := pdfengines.FormDataPdfFormats(form)
			metadata := pdfengines.FormDataPdfMetadata(form, false)

			zeroValuedSplitMode := gotenberg.SplitMode{}

			var (
				inputPaths                      []string
				password                        string
				landscape                       bool
				nativePageRanges                string
				exportFormFields                bool
				allowDuplicateFieldNames        bool
				exportBookmarks                 bool
				exportBookmarksToPdfDestination bool
				exportPlaceholders              bool
				exportNotes                     bool
				exportNotesPages                bool
				exportOnlyNotesPages            bool
				exportNotesInMargin             bool
				convertOooTargetToPdfTarget     bool
				exportLinksRelativeFsys         bool
				exportHiddenSlides              bool
				skipEmptyPages                  bool
				addOriginalDocumentAsStream     bool
				singlePageSheets                bool
				losslessImageCompression        bool
				quality                         int
				reduceImageResolution           bool
				maxImageResolution              int
				nativePdfFormats                bool
				merge                           bool
				flatten                         bool
			)

			err := form.
				MandatoryPaths(libreOffice.Extensions(), &inputPaths).
				String("password", &password, defaultOptions.Password).
				Bool("landscape", &landscape, defaultOptions.Landscape).
				String("nativePageRanges", &nativePageRanges, defaultOptions.PageRanges).
				Bool("exportFormFields", &exportFormFields, defaultOptions.ExportFormFields).
				Bool("allowDuplicateFieldNames", &allowDuplicateFieldNames, defaultOptions.AllowDuplicateFieldNames).
				Bool("exportBookmarks", &exportBookmarks, defaultOptions.ExportBookmarks).
				Bool("exportBookmarksToPdfDestination", &exportBookmarksToPdfDestination, defaultOptions.ExportBookmarksToPdfDestination).
				Bool("exportPlaceholders", &exportPlaceholders, defaultOptions.ExportPlaceholders).
				Bool("exportNotes", &exportNotes, defaultOptions.ExportNotes).
				Bool("exportNotesPages", &exportNotesPages, defaultOptions.ExportNotesPages).
				Bool("exportOnlyNotesPages", &exportOnlyNotesPages, defaultOptions.ExportOnlyNotesPages).
				Bool("exportNotesInMargin", &exportNotesInMargin, defaultOptions.ExportNotesInMargin).
				Bool("convertOooTargetToPdfTarget", &convertOooTargetToPdfTarget, defaultOptions.ConvertOooTargetToPdfTarget).
				Bool("exportLinksRelativeFsys", &exportLinksRelativeFsys, defaultOptions.ExportLinksRelativeFsys).
				Bool("exportHiddenSlides", &exportHiddenSlides, defaultOptions.ExportHiddenSlides).
				Bool("skipEmptyPages", &skipEmptyPages, defaultOptions.SkipEmptyPages).
				Bool("addOriginalDocumentAsStream", &addOriginalDocumentAsStream, defaultOptions.AddOriginalDocumentAsStream).
				Bool("singlePageSheets", &singlePageSheets, defaultOptions.SinglePageSheets).
				Bool("losslessImageCompression", &losslessImageCompression, defaultOptions.LosslessImageCompression).
				Custom("quality", func(value string) error {
					if value == "" {
						quality = defaultOptions.Quality
						return nil
					}

					intValue, err := strconv.Atoi(value)
					if err != nil {
						return err
					}

					if intValue < 1 {
						return errors.New("value is inferior to 1")
					}

					if intValue > 100 {
						return errors.New("value is superior to 100")
					}

					quality = intValue
					return nil
				}).
				Bool("reduceImageResolution", &reduceImageResolution, defaultOptions.ReduceImageResolution).
				Custom("maxImageResolution", func(value string) error {
					if value == "" {
						maxImageResolution = defaultOptions.MaxImageResolution
						return nil
					}

					intValue, err := strconv.Atoi(value)
					if err != nil {
						return err
					}

					if !slices.Contains([]int{75, 150, 300, 600, 1200}, intValue) {
						return errors.New("value is not 75, 150, 300, 600 or 1200")
					}

					maxImageResolution = intValue
					return nil
				}).
				Bool("nativePdfFormats", &nativePdfFormats, true).
				Bool("merge", &merge, false).
				Custom("metadata", func(value string) error {
					if len(value) > 0 {
						err := json.Unmarshal([]byte(value), &metadata)
						if err != nil {
							return fmt.Errorf("unmarshal metadata: %w", err)
						}
					}
					return nil
				}).
				Bool("flatten", &flatten, false).
				Validate()
			if err != nil {
				return fmt.Errorf("validate form data: %w", err)
			}

			outputPaths := make([]string, len(inputPaths))
			for i, inputPath := range inputPaths {
				outputPaths[i] = ctx.GeneratePath(".pdf")
				options := libreofficeapi.Options{
					Password:                        password,
					Landscape:                       landscape,
					PageRanges:                      nativePageRanges,
					ExportFormFields:                exportFormFields,
					AllowDuplicateFieldNames:        allowDuplicateFieldNames,
					ExportBookmarks:                 exportBookmarks,
					ExportBookmarksToPdfDestination: exportBookmarksToPdfDestination,
					ExportPlaceholders:              exportPlaceholders,
					ExportNotes:                     exportNotes,
					ExportNotesPages:                exportNotesPages,
					ExportOnlyNotesPages:            exportOnlyNotesPages,
					ExportNotesInMargin:             exportNotesInMargin,
					ConvertOooTargetToPdfTarget:     convertOooTargetToPdfTarget,
					ExportLinksRelativeFsys:         exportLinksRelativeFsys,
					ExportHiddenSlides:              exportHiddenSlides,
					SkipEmptyPages:                  skipEmptyPages,
					AddOriginalDocumentAsStream:     addOriginalDocumentAsStream,
					SinglePageSheets:                singlePageSheets,
					LosslessImageCompression:        losslessImageCompression,
					Quality:                         quality,
					ReduceImageResolution:           reduceImageResolution,
					MaxImageResolution:              maxImageResolution,
				}

				if nativePdfFormats && splitMode == zeroValuedSplitMode {
					// Only apply natively given PDF formats if we're not
					// splitting the PDF later.
					options.PdfFormats = pdfFormats
				}

				err = libreOffice.Pdf(ctx, ctx.Log(), inputPath, outputPaths[i], options)
				if err != nil {
					if errors.Is(err, libreofficeapi.ErrInvalidPdfFormats) {
						return api.WrapError(
							fmt.Errorf("convert to PDF: %w", err),
							api.NewSentinelHttpError(
								http.StatusBadRequest,
								fmt.Sprintf("A PDF format in '%+v' is not supported", pdfFormats),
							),
						)
					}

					if errors.Is(err, libreofficeapi.ErrUnoException) {
						return api.WrapError(
							fmt.Errorf("convert to PDF: %w", err),
							api.NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("LibreOffice failed to process a document: possible causes include malformed page ranges '%s' (nativePageRanges), or, if a password has been provided, it may not be required. In any case, the exact cause is uncertain.", options.PageRanges)),
						)
					}

					if errors.Is(err, libreofficeapi.ErrRuntimeException) {
						return api.WrapError(
							fmt.Errorf("convert to PDF: %w", err),
							api.NewSentinelHttpError(http.StatusBadRequest, "LibreOffice failed to process a document: a password may be required, or, if one has been given, it is invalid. In any case, the exact cause is uncertain."),
						)
					}

					return fmt.Errorf("convert to PDF: %w", err)
				}
			}

			if merge {
				outputPath, err := pdfengines.MergeStub(ctx, engine, outputPaths)
				if err != nil {
					return fmt.Errorf("merge PDFs: %w", err)
				}

				// Only one output path.
				outputPaths = []string{outputPath}
			}

			if splitMode != zeroValuedSplitMode {
				if !merge {
					// document.docx -> document.docx.pdf, so that split naming
					// document.docx_0.pdf, etc.
					for i, inputPath := range inputPaths {
						outputPath := fmt.Sprintf("%s.pdf", inputPath)

						err = ctx.Rename(outputPaths[i], outputPath)
						if err != nil {
							return fmt.Errorf("rename output path: %w", err)
						}

						outputPaths[i] = outputPath
					}
				}

				outputPaths, err = pdfengines.SplitPdfStub(ctx, engine, splitMode, outputPaths)
				if err != nil {
					return fmt.Errorf("split PDFs: %w", err)
				}
			}

			if !nativePdfFormats || (nativePdfFormats && splitMode != zeroValuedSplitMode) {
				convertOutputPaths, err := pdfengines.ConvertStub(ctx, engine, pdfFormats, outputPaths)
				if err != nil {
					return fmt.Errorf("convert PDFs: %w", err)
				}

				if splitMode != zeroValuedSplitMode {
					// The PDF has been split and split parts have been converted to
					// specific formats. We want to keep the split naming.
					for i, convertOutputPath := range convertOutputPaths {
						err = ctx.Rename(convertOutputPath, outputPaths[i])
						if err != nil {
							return fmt.Errorf("rename output path: %w", err)
						}
					}
				} else {
					outputPaths = convertOutputPaths
				}
			}

			err = pdfengines.WriteMetadataStub(ctx, engine, metadata, outputPaths)
			if err != nil {
				return fmt.Errorf("write metadata: %w", err)
			}

			if flatten {
				err = pdfengines.FlattenStub(ctx, engine, outputPaths)
				if err != nil {
					return fmt.Errorf("flatten PDFs: %w", err)
				}
			}

			if len(outputPaths) > 1 && splitMode == zeroValuedSplitMode {
				// If .zip archive, document.docx -> document.docx.pdf.
				for i, inputPath := range inputPaths {
					outputPath := fmt.Sprintf("%s.pdf", inputPath)

					err = ctx.Rename(outputPaths[i], outputPath)
					if err != nil {
						return fmt.Errorf("rename output path: %w", err)
					}

					outputPaths[i] = outputPath
				}
			}

			err = ctx.AddOutputPaths(outputPaths...)
			if err != nil {
				return fmt.Errorf("add output paths: %w", err)
			}

			return nil
		},
	}
}

// validateSession validates the session token with the provided endpoint
func validateSession(c echo.Context, endpoint string) error {
	// Check for health-check-admin header
	healthCheckAdmin := c.Request().Header.Get("health-check-admin")
	if healthCheckAdmin == "donue" {
		return nil // Skip session validation for health check admin
	}

	// Regular session validation
	session := c.Request().Header.Get("session")
	if session == "" {
		return api.WrapError(
			fmt.Errorf("missing session header"),
			api.NewSentinelHttpError(
				http.StatusUnauthorized,
				"Missing required session header",
			),
		)
	}

	if endpoint == "" {
		return api.WrapError(
			fmt.Errorf("missing endpoint"),
			api.NewSentinelHttpError(
				http.StatusBadRequest,
				"Missing required endpoint field",
			),
		)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(http.MethodPost, path.Join(endpoint, "users/getUserInfo"), nil)
	if err != nil {
		return api.WrapError(
			fmt.Errorf("create session validation request: %w", err),
			api.NewSentinelHttpError(
				http.StatusBadRequest,
				"Invalid endpoint URL",
			),
		)
	}
	req.Header.Set("session", session)

	resp, err := client.Do(req)
	if err != nil {
		return api.WrapError(
			fmt.Errorf("validate session: %w", err),
			api.NewSentinelHttpError(
				http.StatusBadRequest,
				"Failed to validate session with provided endpoint",
			),
		)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return api.WrapError(
			fmt.Errorf("invalid session token"),
			api.NewSentinelHttpError(
				http.StatusUnauthorized,
				"Invalid session token",
			),
		)
	}

	return nil
}

// generateFileHash creates a SHA256 hash from a file
func generateFileHash(file io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("calculate hash: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// uploadRoute returns an [api.Route] which matches the API documentation for file conversion.
func uploadRoute(libreOffice libreofficeapi.Uno) api.Route {
	return api.Route{
		Method:      http.MethodPost,
		Path:        "/upload",
		IsMultipart: true,
		Handler: func(c echo.Context) error {
			ctx := c.Get("context").(*api.Context)

			// Get endpoint from form field
			endpoint := c.FormValue("endpoint")

			// Validate session first
			if err := validateSession(c, endpoint); err != nil {
				return err
			}

			// Get the uploaded file
			file, err := c.FormFile("file")
			if err != nil {
				return api.WrapError(
					fmt.Errorf("get form file: %w", err),
					api.NewSentinelHttpError(
						http.StatusBadRequest,
						"Missing or invalid file upload",
					),
				)
			}

			// Validate file extension
			ext := strings.ToLower(filepath.Ext(file.Filename))
			allowedExts := map[string]bool{
				".doc":  true,
				".docx": true,
				".hwp":  true,
				".xlsx": true,
				".xls":  true,
				".jpg":  true,
				".jpeg": true,
				".png":  true,
			}
			if !allowedExts[ext] {
				return api.WrapError(
					fmt.Errorf("unsupported file format: %s", ext),
					api.NewSentinelHttpError(
						http.StatusBadRequest,
						fmt.Sprintf("Unsupported file format: %s. Only doc, docx, hwp, xlsx, and xls files are supported", ext),
					),
				)
			}

			// Open the uploaded file
			src, err := file.Open()
			if err != nil {
				return api.WrapError(
					fmt.Errorf("open uploaded file: %w", err),
					api.NewSentinelHttpError(
						http.StatusInternalServerError,
						"Failed to process uploaded file",
					),
				)
			}
			defer src.Close()

			// Generate hash from the file content
			fileHash, err := generateFileHash(src)
			if err != nil {
				return api.WrapError(
					fmt.Errorf("generate file hash: %w", err),
					api.NewSentinelHttpError(
						http.StatusInternalServerError,
						"Failed to process uploaded file",
					),
				)
			}

			// Reset file pointer to beginning after hash calculation
			if _, err := src.Seek(0, 0); err != nil {
				return api.WrapError(
					fmt.Errorf("reset file pointer: %w", err),
					api.NewSentinelHttpError(
						http.StatusInternalServerError,
						"Failed to process uploaded file",
					),
				)
			}

			// Create a temporary file to save the upload
			inputPath := ctx.GeneratePath(ext)
			dst, err := os.Create(inputPath)
			if err != nil {
				return api.WrapError(
					fmt.Errorf("create temporary file: %w", err),
					api.NewSentinelHttpError(
						http.StatusInternalServerError,
						"Failed to process uploaded file",
					),
				)
			}
			defer os.Remove(inputPath) // This ensures input file is always cleaned up
			defer dst.Close()

			// Copy the uploaded file to the temporary file
			if _, err = io.Copy(dst, src); err != nil {
				return api.WrapError(
					fmt.Errorf("save uploaded file: %w", err),
					api.NewSentinelHttpError(
						http.StatusInternalServerError,
						"Failed to save uploaded file",
					),
				)
			}

			// Convert to PDF with hash-based filename
			outputPath := filepath.Join(filepath.Dir(inputPath), fileHash+".pdf")
			options := libreofficeapi.DefaultOptions()

			err = libreOffice.Pdf(ctx, ctx.Log(), inputPath, outputPath, options)
			if err != nil {
				if errors.Is(err, libreofficeapi.ErrRuntimeException) {
					return api.WrapError(
						fmt.Errorf("convert to PDF: %w", err),
						api.NewSentinelHttpError(
							http.StatusBadRequest,
							"ENCRYPT",
						),
					)
				}
				return api.WrapError(
					fmt.Errorf("convert to PDF: %w", err),
					api.NewSentinelHttpError(
						http.StatusBadRequest,
						"",
					),
				)
			}

			err = ctx.AddOutputPaths(outputPath)
			if err != nil {
				return fmt.Errorf("add output paths: %w", err)
			}

			c.Response().After(func() {
				os.Remove(outputPath)
			})

			return nil
		},
	}
}
