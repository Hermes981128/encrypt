package encrypt

import "encoding/base64"

func Base64Encode(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}

func Base64Decode(text string) (string, error) {
	// 补全base64
	for len(text)%4 != 0 {
		text += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
