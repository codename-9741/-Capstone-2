package passive

import (
"encoding/json"
"os"
"path/filepath"
"sync"
)

var (
resultsStore = make(map[string]*PassiveResults)
storeMutex   sync.RWMutex
)

func SaveResults(domain string, results *PassiveResults) error {
storeMutex.Lock()
resultsStore[domain] = results
storeMutex.Unlock()

// Also save to file
filename := filepath.Join("/tmp", "nightfall_"+domain+".json")
data, err := json.MarshalIndent(results, "", "  ")
if err != nil {
return err
}

return os.WriteFile(filename, data, 0644)
}

func GetResults(domain string) (*PassiveResults, bool) {
storeMutex.RLock()
defer storeMutex.RUnlock()

results, ok := resultsStore[domain]
return results, ok
}
