// SPDX-License-Identifier: ice License 1.0

package llm

import (
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"strings"
)

var (
	//go:embed prompt_name_mixed.txt
	promptNameMixed string

	//go:embed prompt_name_pic.txt
	promptNamePic string

	//go:embed prompt_name_video.txt
	promptNameVideo string

	//go:embed prompt_image_mixed.txt
	promptImageMixed string

	//go:embed prompt_image_pic.txt
	promptImagePic string

	//go:embed prompt_image_video.txt
	promptImageVideo string
)

var (
	templateNameMixed = template.Must(template.New("name_mixed").Delims("((", "))").Parse(promptNameMixed))
	templateNamePic   = template.Must(template.New("name_pic").Delims("((", "))").Parse(promptNamePic))
	templateNameVideo = template.Must(template.New("name_video").Delims("((", "))").Parse(promptNameVideo))

	templateImageMixed = template.Must(template.New("image_mixed").Delims("((", "))").Parse(promptImageMixed))
	templateImagePic   = template.Must(template.New("image_pic").Delims("((", "))").Parse(promptImagePic))
	templateImageVideo = template.Must(template.New("image_video").Delims("((", "))").Parse(promptImageVideo))
)

var (
	ErrTemplateExecution = errors.New("template execution error")
)

func executeNameTemplate(creator, content string, hasImages, hasVideo bool) (string, error) {
	var tpl *template.Template

	switch {
	case hasImages && hasVideo:
		tpl = templateNameMixed
	case hasImages:
		tpl = templateNamePic
	case hasVideo:
		tpl = templateNameVideo
	default:
		tpl = templateNameMixed
	}

	var sb strings.Builder
	err := tpl.Execute(&sb, map[string]string{
		"Creator": creator,
		"Content": content,
	})
	if err != nil {
		return "", err
	}

	data := sb.String()
	if data == "" {
		return "", fmt.Errorf("%w: resulted in empty string", ErrTemplateExecution)
	}

	return sb.String(), nil
}

func executeImageTemplate(creator, content, name, ticker string, hasImages, hasVideo bool) (string, error) {
	var tpl *template.Template

	switch {
	case hasImages && hasVideo:
		tpl = templateImageMixed
	case hasImages:
		tpl = templateImagePic
	case hasVideo:
		tpl = templateImageVideo
	default:
		tpl = templateImageMixed
	}

	var sb strings.Builder
	err := tpl.Execute(&sb, map[string]string{
		"Creator": creator,
		"Content": content,
		"Name":    name,
		"Ticker":  ticker,
	})
	if err != nil {
		return "", err
	}

	data := sb.String()
	if data == "" {
		return "", fmt.Errorf("%w: resulted in empty string", ErrTemplateExecution)
	}

	return sb.String(), nil
}
