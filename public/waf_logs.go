package public

import (
	"fmt"
	"os"
	"path/filepath"
)

func GetHistorySiteLogs(path string) (map[string]int64, error) {
	result := make(map[string]int64)

	if !FileExists(path) {
		return result, fmt.Errorf("目录不存在: %s", path)
	}

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		relativePath, err := filepath.Rel(path, filePath)
		if err != nil {
			relativePath = info.Name()
		}

		result[relativePath] = info.Size()

		return nil
	})

	if err != nil {
		return result, fmt.Errorf("遍历目录失败: %v", err)
	}

	return result, nil
}
