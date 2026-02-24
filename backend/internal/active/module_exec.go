package active

import (
	"sync/atomic"
)

func (s *ActiveScanner) markModuleAttempted() {
	atomic.AddInt64(&s.modulesAttempted, 1)
}

func (s *ActiveScanner) markModuleCompleted() {
	atomic.AddInt64(&s.modulesCompleted, 1)
}

func (s *ActiveScanner) markModuleErrored() {
	atomic.AddInt64(&s.modulesErrored, 1)
}

func (s *ActiveScanner) markModuleSkipped() {
	atomic.AddInt64(&s.modulesSkipped, 1)
}

// runIf executes fn only if the module is enabled and instruments module success/failure.
// A module is considered errored when it attempted >=1 requests and all of them errored.
func (s *ActiveScanner) runIf(moduleID string, fn func()) {
	if s.config == nil || !s.config.ShouldRunModule(moduleID) {
		s.setModuleStatus(moduleID, "skipped")
		return
	}

	startTotal := atomic.LoadInt64(&s.requestsTotal)
	startErrored := atomic.LoadInt64(&s.requestsErrored)

	s.setModuleStatus(moduleID, "running")
	s.markModuleAttempted()
	defer func() {
		if recover() != nil {
			s.markModuleErrored()
			s.setModuleStatus(moduleID, "failed")
			return
		}

		deltaTotal := atomic.LoadInt64(&s.requestsTotal) - startTotal
		deltaErrored := atomic.LoadInt64(&s.requestsErrored) - startErrored
		if deltaTotal > 0 && deltaErrored == deltaTotal {
			// If we know connectivity is down globally, don't treat individual modules as broken.
			if atomic.LoadInt32(&s.connectivityOK) == 0 {
				s.markModuleSkipped()
				s.setModuleStatus(moduleID, "skipped")
				return
			}
			s.markModuleErrored()
			s.setModuleStatus(moduleID, "failed")
			return
		}
		s.markModuleCompleted()
		s.setModuleStatus(moduleID, "completed")
	}()

	fn()
}
