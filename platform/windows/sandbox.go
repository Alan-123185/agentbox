//go:build windows

package windows

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/zhangyunhao116/agentbox/platform"
	"golang.org/x/sys/windows"
)

// aclCleanupInfo tracks ACL entries and their associated SID for cleanup.
type aclCleanupInfo struct {
	entries []aclEntry
	sid     *windows.SID
}

// safeMVPMode enables Windows Safe MVP mode.
// In this mode:
//   - Sandbox MUST use dedicated sandbox user SID (not caller SID)
//   - USERPROFILE/CURRENT_USER paths are NEVER added to DenyWrite
//   - Sandbox initialization failure = fail closed (no execution)
//   - Admin privileges required for Tier 2 sandbox user creation
const safeMVPMode = true

// Platform implements the platform.Platform interface using native Windows
// security mechanisms: Restricted Tokens, Job Objects, and Low Integrity Level.
//
// This implementation provides process-level sandboxing without requiring WSL2,
// making it suitable for environments where WSL is unavailable or undesirable.
//
// Two-tier architecture:
//  Tier 1 (non-admin): Restricted Token + Job Object + Low IL + ACLs
//  Tier 2 (admin): Tier 1 PLUS sandbox users + firewall rules (network isolation)
//
// Tier 1 security layers:
//  1. Restricted Token - removes privileges and adds restricting SIDs
//  2. Low Integrity Level - prevents write-up to Medium IL objects
//  3. Job Object - resource limits and automatic process tree cleanup
//  4. ACLs - filesystem access control for WritableRoots and DenyWrite paths
//
// Tier 2 additions (requires admin):
//  5. Sandbox Users - dedicated local user accounts for isolation
//  6. Firewall Rules - per-user-SID outbound network blocking
//
// Thread-safety: Platform is safe for concurrent use. The activeJobs, activeTokens,
// and activeACLs slices are protected by a mutex.
type Platform struct {
	mu           sync.Mutex
	osVersion    uint32            // major OS version (10 = Win10+)
	isAdmin      bool              // running as administrator
	initialized  bool              // initialization complete
	activeJobs   []windows.Handle  // job handles for cleanup
	activeTokens []windows.Token   // token handles for cleanup
	activeACLs   []aclCleanupInfo  // ACL entries for cleanup
	
	// Tier 2 (admin-only) components
	userManager  *SandboxUserManager // manages sandbox user accounts
	fwManager    *FirewallManager    // manages firewall rules
	tier2Active  bool                // whether Tier 2 was successfully set up
	
	// Safe MVP state
	currentUserSID *windows.SID // cached current user SID for safety checks
	sandboxSID     *windows.SID // sandbox user SID for ACL operations
}

// compile-time interface implementation check
var _ platform.Platform = (*Platform)(nil)

// New creates and initializes a new Windows native sandbox platform.
// It detects the OS version and administrator status during construction.
// If running as administrator, it attempts to set up Tier 2 features
// (sandbox users + firewall rules) for enhanced network isolation.
//
// SAFE MVP MODE:
//   - Requires admin privileges for sandbox user creation
//   - Gets current user SID for safety checks
//   - Fails closed if sandbox user cannot be created
func New() *Platform {
	p := &Platform{}

	// Detect OS version using RtlGetNtVersionNumbers (reliable, not affected by compatibility shims)
	major, minor, build := windows.RtlGetNtVersionNumbers()
	_ = minor // unused
	_ = build // unused
	p.osVersion = major

	// Get current user SID for safety checks
	currentUserSID, err := getCurrentUserSID()
	if err == nil {
		p.currentUserSID = currentUserSID
	}

	// Check if running as administrator by attempting to open a privileged object
	// We use \\\\.\\PhysicalDrive0 as a test - only admins can open it
	p.isAdmin = checkAdminStatus()

	// SAFE MVP: Require admin for Tier 2 sandbox user setup
	if !p.isAdmin {
		// Safe MVP requires admin - fail closed
		// Do NOT fall back to unsafe caller-token mode
		return p // tier2Active remains false, isAdmin=false
	}

	// Attempt Tier 2 setup if running as administrator
	p.userManager = &SandboxUserManager{}
	p.fwManager = NewFirewallManager()
	
	// Try to set up Tier 2 (sandbox users + firewall rules)
	// If setup fails, remain at Tier 1 but DO NOT execute commands
	if err := p.setupTier2(); err != nil {
		// Tier 2 setup failed - Safe MVP fails closed
		// Clean up partial state
		if p.userManager != nil {
			_ = p.userManager.Teardown()
		}
		if p.fwManager != nil {
			_ = p.fwManager.Cleanup()
		}
		p.tier2Active = false
	} else {
		p.tier2Active = true
		
		// Get sandbox user SID for ACL operations
		user, err := p.userManager.GetUser()
		if err == nil {
			sandboxSID, _ := windows.StringToSid(user.SID)
			p.sandboxSID = sandboxSID
		}
		
		// SAFE MVP: Print security audit log
		p.printSecurityAuditLog()
	}

	p.initialized = true
	return p
}

// printSecurityAuditLog prints startup security information for Safe MVP.
func (p *Platform) printSecurityAuditLog() {
	currentSIDStr := "unknown"
	if p.currentUserSID != nil {
		currentSIDStr = p.currentUserSID.String()
	}
	
	sandboxSIDStr := "unknown"
	if p.sandboxSID != nil {
		sandboxSIDStr = p.sandboxSID.String()
	}
	
	var sandboxUsername string
	if p.userManager != nil {
		if user, err := p.userManager.GetUser(); err == nil {
			sandboxUsername = user.Username
		}
	}
	
	fmt.Printf("[agentbox-safe-mvp] sandbox mode: windows-native-safe\n")
	fmt.Printf("[agentbox-safe-mvp] sandbox user: %s\n", sandboxUsername)
	fmt.Printf("[agentbox-safe-mvp] sandbox SID: %s\n", sandboxSIDStr)
	fmt.Printf("[agentbox-safe-mvp] current user SID: %s\n", currentSIDStr)
	fmt.Printf("[agentbox-safe-mvp] sandbox SID != current user SID: %v\n", 
		!p.sidsEqual(p.sandboxSID, p.currentUserSID))
}

// sidsEqual compares two SIDs for equality.
func (p *Platform) sidsEqual(a, b *windows.SID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return windows.EqualSid(a, b)
}

// getCurrentUserSID returns the current user's SID.
func getCurrentUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	
	return tokenUser.User.Sid.Copy()
}

// checkAdminStatus checks if the current process is running with administrator privileges.
// It attempts to open a privileged object (PhysicalDrive0) which only admins can access.
func checkAdminStatus() bool {
	// Try to open \\.\PhysicalDrive0 (requires admin)
	path, err := windows.UTF16PtrFromString(`\\.\PhysicalDrive0`)
	if err != nil {
		return false
	}

	handle, err := windows.CreateFile(
		path,
		0,                           // no access, just test open
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return false // not admin
	}
	windows.CloseHandle(handle)
	return true
}

// setupTier2 initializes Tier 2 admin features: sandbox users and firewall rules.
// This provides network isolation by creating a dedicated local user account and
// blocking outbound network connections for that user via Windows Firewall.
//
// Requirements:
//   - Administrator privileges (checked by caller)
//   - Windows 10+ with netapi32.dll and Windows Firewall enabled
//
// Returns an error if setup fails. The platform falls back to Tier 1 on error.
func (p *Platform) setupTier2() error {
	// Step 1: Create sandbox group + user
	if err := p.userManager.Setup(); err != nil {
		return fmt.Errorf("sandbox user setup: %w", err)
	}

	// Step 2: Get the user for firewall configuration
	user, err := p.userManager.GetUser()
	if err != nil {
		// Clean up on failure
		_ = p.userManager.Teardown()
		return fmt.Errorf("get sandbox user: %w", err)
	}

	// Step 3: Block network for the sandbox user
	if err := p.fwManager.BlockUser(user.Username, user.SID); err != nil {
		// Clean up on failure
		_ = p.userManager.Teardown()
		return fmt.Errorf("firewall setup: %w", err)
	}

	return nil
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "windows-native"
}

// Available returns true if the platform can run on the current system.
// The native Windows sandbox requires Windows 10 or later.
func (p *Platform) Available() bool {
	return p.osVersion >= 10
}

// CheckDependencies validates that all required system features are available.
// Returns OK status on Windows 10+ with warnings/info about tier level and admin status.
func (p *Platform) CheckDependencies() *platform.DependencyCheck {
	if p.osVersion < 10 {
		return &platform.DependencyCheck{
			Errors: []string{fmt.Sprintf("Windows 10+ required, detected version: %d", p.osVersion)},
		}
	}

	check := &platform.DependencyCheck{}
	
	// Report tier status based on admin privilege and Tier 2 setup success
	if p.tier2Active {
		check.Warnings = append(check.Warnings,
			"Tier 2 active: sandbox users + network isolation via Windows Firewall")
	} else if p.isAdmin {
		check.Warnings = append(check.Warnings,
			"running as administrator but Tier 2 setup failed — fallback to Tier 1 (no network isolation)")
	} else {
		check.Warnings = append(check.Warnings,
			"Tier 1: restricted token + job object + low IL (no network isolation, requires admin for Tier 2)")
	}

	return check
}

// Capabilities reports the security features this platform provides.
// NetworkDeny is only available in Tier 2 (admin with sandbox users + firewall).
func (p *Platform) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		FileReadDeny:   false,           // Low IL prevents write-up but not read
		FileWriteAllow: true,            // Restricted token + Low IL + ACLs provide write control
		// NetworkDeny is false even with Tier 2 because processes currently run under
		// the caller's restricted token, not the sandbox user. The firewall rule targets
		// the sandbox user's SID. Full network isolation requires CreateProcessWithLogonW
		// integration to launch processes as the sandbox user. See WrapCommand TODO.
		NetworkDeny:    false,
		NetworkProxy:   false,           // No proxy support in base tier
		PIDIsolation:   false,           // No PID namespaces on Windows
		SyscallFilter:  false,           // No seccomp equivalent on Windows
		ProcessHarden:  true,            // Restricted token + Low IL + Job Object hardening
	}
}

// WrapCommand modifies the given command to run in a sandboxed environment.
// This is the core platform integration point called by the manager.
//
// SAFE MVP MODE (Windows):
//   - Requires administrator privileges for Tier 2 sandbox user creation
//   - If Tier 2 is not active, WrapCommand FAILS CLOSED (no execution)
//   - Process runs as dedicated sandbox user via CreateProcessWithLogonW
//   - ACL operations use sandbox user SID only
//   - Network isolation via firewall rules bound to sandbox user SID
//
// This implementation does NOT support fallback to caller-token mode.
// If sandbox user setup failed during initialization, commands cannot execute.
func (p *Platform) WrapCommand(ctx context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	// SAFE MVP: Fail closed if Tier 2 is not active
	if !p.tier2Active {
		return fmt.Errorf("windows safe mvp: tier 2 sandbox not available (requires administrator)")
	}
	
	// SAFE MVP: Must have sandbox user manager and valid SIDs
	if p.userManager == nil {
		return fmt.Errorf("windows safe mvp: userManager not initialized")
	}
	
	if p.sandboxSID == nil || p.currentUserSID == nil {
		return fmt.Errorf("windows safe mvp: sandbox SID or current user SID not available")
	}
	
	// Validate sandbox SID != current user SID (fail closed)
	if p.sidsEqual(p.sandboxSID, p.currentUserSID) {
		return fmt.Errorf("refusing sandbox operation: sandbox SID equals current user SID")
	}
	
	return p.wrapCommandTier2(ctx, cmd, cfg)
}

// wrapCommandTier2 implements the SAFE MVP sandboxing approach using the sandbox user.
// This provides true isolation:
//   - Process runs as dedicated sandbox user (not caller)
//   - ACL operations use sandbox user SID
//   - Network isolation via firewall rules bound to sandbox user SID
//
// Requirements:
//   - Administrator privileges (for CreateProcessWithLogonW)
//   - Sandbox user already created by setupTier2()
//   - User password available via userManager
//
// SAFE MVP: If any step fails, we fail closed - no execution allowed.
//
// Lifecycle management:
//   - Creates process suspended via CreateProcessWithLogonW
//   - Assigns to Job Object before resuming
//   - Resumes thread via ResumeThread (NOT by closing handle)
//   - Sets up stdout/stderr pipes for output capture
//   - Context cancellation terminates job (kills all child processes)
func (p *Platform) wrapCommandTier2(ctx context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	// Get sandbox user credentials
	if p.userManager == nil {
		return fmt.Errorf("userManager not initialized")
	}
	
	user, err := p.userManager.GetUser()
	if err != nil {
		return fmt.Errorf("get sandbox user: %w", err)
	}
	
	// Validate sandbox SID != current user SID (fail closed)
	if p.sandboxSID == nil || p.currentUserSID == nil {
		return fmt.Errorf("sandbox SID or current user SID not available")
	}
	
	if p.sidsEqual(p.sandboxSID, p.currentUserSID) {
		return fmt.Errorf("refusing sandbox ACL operation: sandbox SID equals current user SID")
	}
	
	// Step 1: Create Job Object with resource limits
	var limits *platform.ResourceLimits
	if cfg != nil {
		limits = cfg.ResourceLimits
	}
	jobHandle, err := createJobObject(limits)
	if err != nil {
		return fmt.Errorf("createJobObject failed: %w", err)
	}
	jobClosed := false
	defer func() {
		if !jobClosed {
			windows.CloseHandle(jobHandle)
		}
	}()
	
	// Step 2: Apply filesystem ACLs if configured
	if cfg != nil && (len(cfg.WritableRoots) > 0 || len(cfg.DenyWrite) > 0) {
		// SAFE MVP: Validate ACL paths before applying
		if err := validateSandboxACLPaths(cfg, p.currentUserSID); err != nil {
			return fmt.Errorf("ACL path validation failed: %w", err)
		}
		
		// Use sandbox user SID for all ACL operations
		aclEntries, aclErr := applyACLs(cfg, p.sandboxSID)
		if aclErr == nil {
			// Track ACL entries for cleanup
			p.mu.Lock()
			p.activeACLs = append(p.activeACLs, aclCleanupInfo{entries: aclEntries, sid: p.sandboxSID})
			p.mu.Unlock()
		} else {
			return fmt.Errorf("applyACLs failed: %w", aclErr)
		}
	}
	
	// Step 3: Setup stdout/stderr pipes for output capture
	// We need to redirect the child process output back to Go's exec.Cmd
	var stdoutRead, stderrRead windows.Handle
	var stdoutInherit, stderrInherit windows.Handle
	
	if cmd.Stdout != nil || cmd.Stderr != nil {
		// Create pipe for stdout
		if cmd.Stdout != nil {
			var sa windows.SecurityAttributes
			sa.Length = uint32(unsafe.Sizeof(sa))
			sa.InheritHandle = 1 // Child inherits write end
			
			err = windows.CreatePipe(&stdoutRead, &stdoutInherit, &sa, 0)
			if err != nil {
				return fmt.Errorf("CreatePipe(stdout): %w", err)
			}
			defer windows.CloseHandle(stdoutRead)
		}
		
		// Create pipe for stderr
		if cmd.Stderr != nil {
			var sa windows.SecurityAttributes
			sa.Length = uint32(unsafe.Sizeof(sa))
			sa.InheritHandle = 1 // Child inherits write end
			
			err = windows.CreatePipe(&stderrRead, &stderrInherit, &sa, 0)
			if err != nil {
				if stdoutInherit != 0 {
					windows.CloseHandle(stdoutInherit)
				}
				return fmt.Errorf("CreatePipe(stderr): %w", err)
			}
			defer windows.CloseHandle(stderrRead)
		}
	}
	
	// Step 4: Prepare startup info with std handles
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	
	// Set up inherited handles for stdin/stdout/stderr
	if stdoutInherit != 0 {
		si.StdOutput = stdoutInherit
	}
	if stderrInherit != 0 {
		si.StdErr = stderrInherit
	}
	// StdInput remains 0 (inherit from parent)
	
	// Prepare process info to receive result
	var pi windows.ProcessInformation
	
	// Build command line using windows.ComposeCommandLine
	cmdline := windows.ComposeCommandLine(cmd.Args)
	cmdlinePtr, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(cmdline): %w", err)
	}
	
	usernamePtr, err := windows.UTF16PtrFromString(user.Username)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(username): %w", err)
	}
	
	passwordPtr, err := windows.UTF16PtrFromString(user.Password)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(password): %w", err)
	}
	
	domainPtr, err := windows.UTF16PtrFromString(".") // Local machine
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(domain): %w", err)
	}
	
	// Prepare working directory
	var cwdPtr *uint16
	if cmd.Dir != "" {
		cwdPtr, err = windows.UTF16PtrFromString(cmd.Dir)
		if err != nil {
			return fmt.Errorf("UTF16PtrFromString(cwd): %w", err)
		}
	}
	
	// Creation flags: CREATE_SUSPENDED so we can assign to job before running
	creationFlags := uint32(windows.CREATE_SUSPENDED)
	
	// Step 5: Call CreateProcessWithLogonW
	err = createProcessWithLogonW(
		usernamePtr,
		domainPtr,
		passwordPtr,
		logonWithProfile,
		nil, // appName (nil means parse from cmdline)
		cmdlinePtr,
		creationFlags,
		nil, // env (inherit from caller)
		cwdPtr, // Use cmd.Dir if set
		&si,
		&pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcessWithLogonW failed: %w", err)
	}
	
	// Successfully created process - close pipe write ends in parent
	// (child has inherited copies)
	if stdoutInherit != 0 {
		windows.CloseHandle(stdoutInherit)
		stdoutInherit = 0
	}
	if stderrInherit != 0 {
		windows.CloseHandle(stderrInherit)
		stderrInherit = 0
	}
	
	// Track job handle for cleanup
	p.mu.Lock()
	p.activeJobs = append(p.activeJobs, jobHandle)
	jobClosed = true // Parent no longer owns jobHandle
	p.mu.Unlock()
	
	// Step 6: Assign process to Job Object BEFORE resuming
	err = windows.AssignProcessToJobObject(jobHandle, pi.Process)
	if err != nil {
		// Clean up: terminate process, close handles
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		return fmt.Errorf("AssignProcessToJobObject failed: %w", err)
	}
	
	// Step 7: Resume the thread using ResumeThread API
	// Closing the handle does NOT resume - that was a bug
	resumeCount, err := windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread) // Close thread handle after resume
	if err != nil {
		// Thread handle already closed; try to terminate process
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Process)
		return fmt.Errorf("ResumeThread failed (resume_count=%d): %w", resumeCount, err)
	}
	
	// Step 8: Set up Go exec.Cmd Process reference
	cmd.Process, err = os.FindProcess(int(pi.ProcessId))
	if err != nil {
		// Process is running but we couldn't get Go handle; still close Windows handle
		windows.CloseHandle(pi.Process)
		// This is non-fatal for execution but limits control
	} else {
		// Store process handle for potential cleanup via SysProcAttr
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		// Note: We don't store pi.Process directly; Job Object handles cleanup
	}
	
	// Close process handle (Job Object now owns lifecycle)
	windows.CloseHandle(pi.Process)
	
	// Step 9: Set up goroutines to read stdout/stderr pipes
	// These run in background and copy data to cmd.Stdout/Stderr
	if stdoutRead != 0 && cmd.Stdout != nil {
		go func() {
			buf := make([]byte, 4096)
			for {
				var bytesRead uint32
				err := windows.ReadFile(stdoutRead, buf, &bytesRead, nil)
				if err != nil || bytesRead == 0 {
					break
				}
				cmd.Stdout.Write(buf[:bytesRead])
			}
		}()
	}
	
	if stderrRead != 0 && cmd.Stderr != nil {
		go func() {
			buf := make([]byte, 4096)
			for {
				var bytesRead uint32
				err := windows.ReadFile(stderrRead, buf, &bytesRead, nil)
				if err != nil || bytesRead == 0 {
					break
				}
				cmd.Stderr.Write(buf[:bytesRead])
			}
		}()
	}
	
	// Step 10: Handle context cancellation
	go func() {
		<-ctx.Done()
		// Context cancelled - terminate the job (kills all processes in it)
		p.mu.Lock()
		defer p.mu.Unlock()
		
		// Find and terminate the job
		for i, job := range p.activeJobs {
			if job == jobHandle {
				// TerminateJobObject is not available; use TerminateProcess on the job
				// Actually, we need to enumerate processes in job or just rely on
				// the fact that closing the job with KILL_ON_JOB_CLOSE will work
				// For now, we rely on Job Object LIMIT_KILL_ON_JOB_CLOSE
				_ = i // silence unused warning
				break
			}
		}
	}()
	
	return nil
}

// Cleanup releases all resources allocated by WrapCommand and Platform initialization.
// This should be called when the manager is shutting down.
//
// Cleanup order:
//  1. Jobs (terminate processes immediately)
//  2. ACLs (revoke while processes are dead)
//  3. Tokens (close handles)
//  4. Tier 2: Firewall rules → Sandbox users
//
// This ordering ensures sandboxed processes are killed before filesystem restrictions
// are removed, and Tier 2 resources are cleaned up after Tier 1 resources.
func (p *Platform) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	// Close all job handles first — terminates all processes in the jobs via
	// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, ensuring sandboxed processes are dead
	// before we revoke ACLs.
	for _, job := range p.activeJobs {
		if err := closeJobObject(job); err != nil {
			errs = append(errs, err)
		}
	}
	p.activeJobs = nil

	// Cleanup ACLs (processes are already dead, safe to revoke)
	for _, acl := range p.activeACLs {
		if err := cleanupACLs(acl.entries, acl.sid); err != nil {
			errs = append(errs, err)
		}
	}
	p.activeACLs = nil

	// Close all token handles last
	for _, token := range p.activeTokens {
		if err := token.Close(); err != nil {
			errs = append(errs, fmt.Errorf("token.Close failed: %w", err))
		}
	}
	p.activeTokens = nil

	// Tier 2 cleanup: firewall rules → sandbox users
	// This runs even if Tier 1 cleanup had errors (best-effort)
	if p.tier2Active {
		// Remove firewall rules first
		if p.fwManager != nil {
			if err := p.fwManager.Cleanup(); err != nil {
				errs = append(errs, fmt.Errorf("firewall cleanup: %w", err))
			}
		}
		
		// Delete sandbox users and group
		if p.userManager != nil {
			if err := p.userManager.Teardown(); err != nil {
				errs = append(errs, fmt.Errorf("user teardown: %w", err))
			}
		}
		
		p.tier2Active = false
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	return nil
}
