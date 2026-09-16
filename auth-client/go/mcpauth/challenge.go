package mcpauth

import (
	"fmt"
	"regexp"
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
	value := fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL)
	if len(scopes) > 0 {
		value += fmt.Sprintf(` scope="%s"`, strings.Join(scopes, " "))
	}
	return map[string]string{"WWW-Authenticate": value}
}
