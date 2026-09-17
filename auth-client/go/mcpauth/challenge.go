package mcpauth

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type ProtectedResourceChallenge struct {
	Scheme           string
	ResourceMetadata string
	Scope            string
}

var resourceMetadataPattern = regexp.MustCompile(`resource_metadata="([^"]+)"`)
var scopePattern = regexp.MustCompile(`scope="([^"]+)"`)

func ParseWWWAuthenticate(value string) ProtectedResourceChallenge {
	scheme := value
	if index := len(value); index > 0 {
		for i, char := range value {
			if char == ' ' {
				scheme = value[:i]
				break
			}
		}
	}
	result := ProtectedResourceChallenge{Scheme: scheme}
	if match := resourceMetadataPattern.FindStringSubmatch(value); len(match) == 2 {
		result.ResourceMetadata = match[1]
	}
	if match := scopePattern.FindStringSubmatch(value); len(match) == 2 {
		result.Scope = match[1]
	}
	return result
}
func UnauthorizedHeaders(metadataURL string, scopes []string) map[string]string {
	value := fmt.Sprintf(`Bearer resource_metadata=%s`, strconv.Quote(metadataURL))
	if len(scopes) > 0 {
		value += fmt.Sprintf(`, scope=%s`, strconv.Quote(strings.Join(scopes, " ")))
	}
	return map[string]string{"WWW-Authenticate": value}
}

func UnauthorizedHeadersForError(metadataURL string, scopes []string, code, description string) map[string]string {
	value := UnauthorizedHeaders(metadataURL, scopes)["WWW-Authenticate"]
	if code != "" {
		value += fmt.Sprintf(`, error=%s`, strconv.Quote(code))
	}
	if description != "" {
		value += fmt.Sprintf(`, error_description=%s`, strconv.Quote(description))
	}
	return map[string]string{"WWW-Authenticate": value}
}
