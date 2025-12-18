package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"flaregate/internal/config"
)

type Runner struct {
	Process *exec.Cmd
	Mutex   sync.Mutex
	LogFile string
}

func NewRunner(logFile string) *Runner {
	return &Runner{
		LogFile: logFile,
	}
}

func (tr *Runner) Start(cfg *config.Config) error {
	tr.Mutex.Lock()
	defer tr.Mutex.Unlock()

	if tr.Process != nil && tr.Process.Process != nil {
		// Check if running
		if tr.Process.ProcessState == nil {
			return nil // Already running
		}
	}

	if cfg.TunnelToken == "" {
		return fmt.Errorf("no tunnel token found")
	}

	// Create log file if not exists
	logFile, err := os.OpenFile(tr.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	cmd := exec.Command("cloudflared", "tunnel", "run", "--token", cfg.TunnelToken)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		return err
	}

	tr.Process = cmd
	
	// Wait in background to release zombies, but don't block
	go func() {
		cmd.Wait()
	}()

	return nil
}

func (tr *Runner) Stop() error {
	tr.Mutex.Lock()
	defer tr.Mutex.Unlock()

	if tr.Process != nil && tr.Process.Process != nil {
		if err := tr.Process.Process.Kill(); err != nil {
			return err
		}
		tr.Process = nil
	}
	return nil
}

func (tr *Runner) Restart(cfg *config.Config) error {
	tr.Stop()
	time.Sleep(1 * time.Second)
	return tr.Start(cfg)
}

func (tr *Runner) IsRunning() bool {
	tr.Mutex.Lock()
	defer tr.Mutex.Unlock()
	return tr.Process != nil && tr.Process.ProcessState == nil // nil state means still running
}
