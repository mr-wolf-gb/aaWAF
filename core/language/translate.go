package language

var (
	currentLang = CN
)

// SetLang sets the current language for translation.
func SetLang(lang string) {
	for _, l := range VALID_LANGUAGE {
		if l == lang {
			currentLang = lang
			return
		}
	}
}

func Locate(s string) string {
	if val, ok := TRANS_MAP[currentLang][s]; ok {
		return val
	}
	return s
}
