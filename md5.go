package encrypt

import (
	"crypto/md5"
	"encoding/hex"
)

func Md5(text string) string {
	ins := md5.New()
	ins.Write([]byte(text))
	return hex.EncodeToString(ins.Sum(nil))
}
