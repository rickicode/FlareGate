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
	Process   *exec.Cmd
	Mutex     sync.Mutex
	LogFile   string
	logHandle *os.File
}

func NewRunner(logFile string) *Runner {
	return &Runner{LogFile: logFile}
}

func (tr *Runner) isProcessRunningLocked() bool {
	return tr.Process != nil && tr.Process.Process != nil && tr.Process.ProcessState == nil
}

func (tr *Runner) closeLogHandleLocked() {
	if tr.logHandle != nil {
		_ = tr.logHandle.Close()
		tr.logHandle = nil
	}
}

func (tr *Runner) Start(cfg *config.Config) error {
	tr.Mutex.Lock()
	defer tr.Mutex.Unlock()

	if tr.isProcessRunningLocked() {
		return nil
	}
	if cfg == nil {
		return fmt.Errorf("nil tunnel config")
	}
	if cfg.TunnelToken == "" {
		return fmt.Errorf("no tunnel token found")
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return fmt.Errorf("failed to create data dir: %w", err)
	}

	logFile, err := os.OpenFile(tr.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	cmd := exec.Command("cloudflared", "tunnel", "--no-autoupdate", "run", "--token", cfg.TunnelToken)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}

	tr.Process = cmd
	tr.logHandle = logFile

	go func(cmd *exec.Cmd) {
		err := cmd.Wait()

		tr.Mutex.Lock()
		defer tr.Mutex.Unlock()

		if tr.Process == cmd {
			tr.Process = nil
		}
		tr.closeLogHandleLocked()

		if err != nil {
			fmt.Printf("[Tunnel] cloudflared exited: %v\n", err)
		}
	}(cmd)

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
	tr.closeLogHandleLocked()
	return nil
}

func (tr *Runner) Restart(cfg *config.Config) error {
	if err := tr.Stop(); err != nil {
		return err
	}
	time.Sleep(1 * time.Second)
	return tr.Start(cfg)
}

func (tr *Runner) IsRunning() bool {
	tr.Mutex.Lock()
	defer tr.Mutex.Unlock()
	return tr.isProcessRunningLocked()
}
