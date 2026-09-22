// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// SecurityPolicy defines rules for contract execution and deployment
type SecurityPolicy struct {
	// MaxCodeSize is the maximum contract code size in bytes
	MaxCodeSize uint64

	// MaxMemoryPages is the maximum WASM memory pages allowed
	MaxMemoryPages uint32

	// MaxCallDepth is the maximum call nesting depth
	MaxCallDepth uint32

	// MaxStorageSize is the maximum total storage per contract in bytes
	MaxStorageSize uint64

	// MaxExecutionTime is the maximum execution duration in milliseconds
	MaxExecutionTimeMs uint64

	// MaxGasPerCall is the maximum gas per single call
	MaxGasPerCall uint64

	// ReentrancyProtection enables reentrancy guards
	ReentrancyProtection bool

	// RequireABIVersion enforces specific ABI versions
	RequireABIVersion bool

	// AllowedRuntimes specifies which runtimes are permitted
	AllowedRuntimes []string

	// ForbiddenOpcodes are WASM opcodes that should be rejected
	ForbiddenOpcodes []string

	// TransferLimit is the maximum amount per transfer
	TransferLimit *big.Int
}

// DefaultSecurityPolicy returns a production-safe default policy
func DefaultSecurityPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		MaxCodeSize:          10 * 1024 * 1024, // 10 MB
		MaxMemoryPages:       512,              // 32 MB
		MaxCallDepth:         64,
		MaxStorageSize:       100 * 1024 * 1024, // 100 MB
		MaxExecutionTimeMs:   30000,             // 30 seconds
		MaxGasPerCall:        10_000_000,
		ReentrancyProtection: true,
		RequireABIVersion:    true,
		AllowedRuntimes:      []string{RuntimeNative, RuntimeSVM1, RuntimeWASM},
		ForbiddenOpcodes:     []string{"loop", "br_table"}, // Bounded loops only
		TransferLimit:        big.NewInt(math.MaxInt64),
	}
}

// SecurityAudit performs a security audit on contract code
type SecurityAudit struct {
	ContractAddress string
	Runtime         string
	Issues          []SecurityIssue
	Passed          bool
	Score           uint32 // 0-100
}

// SecurityIssue describes a potential security problem
type SecurityIssue struct {
	Severity       IssueSeverity
	Category       IssueCategory
	Title          string
	Description    string
	Line           int
	Recommendation string
	Confidence     uint32 // 0-100
}

// IssueSeverity indicates the severity level
type IssueSeverity string

const (
	SeverityCritical IssueSeverity = "critical"
	SeverityHigh     IssueSeverity = "high"
	SeverityMedium   IssueSeverity = "medium"
	SeverityLow      IssueSeverity = "low"
	SeverityInfo     IssueSeverity = "info"
)

// IssueCategory categorizes the type of issue
type IssueCategory string

const (
	CategoryReentrancy        IssueCategory = "reentrancy"
	CategoryIntegerOverflow   IssueCategory = "integer_overflow"
	CategoryUnboundedLoop     IssueCategory = "unbounded_loop"
	CategoryUncheckedCall     IssueCategory = "unchecked_call"
	CategoryArithmeticError   IssueCategory = "arithmetic_error"
	CategoryOutOfBounds       IssueCategory = "out_of_bounds"
	CategoryAccessControl     IssueCategory = "access_control"
	CategoryStorageCorruption IssueCategory = "storage_corruption"
	CategoryInfoLeak          IssueCategory = "information_leak"
	CategoryDenialOfService   IssueCategory = "denial_of_service"
)

// SecurityAuditor performs security audits on contracts
type SecurityAuditor struct {
	policy *SecurityPolicy
}

// NewSecurityAuditor creates a new security auditor
func NewSecurityAuditor(policy *SecurityPolicy) *SecurityAuditor {
	if policy == nil {
		policy = DefaultSecurityPolicy()
	}
	return &SecurityAuditor{policy: policy}
}

// AuditDeployment checks contract deployment for security issues
func (sa *SecurityAuditor) AuditDeployment(address string, meta *ContractMeta, code []byte) *SecurityAudit {
	audit := &SecurityAudit{
		ContractAddress: address,
		Runtime:         "",
		Issues:          []SecurityIssue{},
		Passed:          true,
		Score:           100,
	}
	if meta != nil {
		audit.Runtime = meta.Runtime
	}

	if meta == nil {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityCritical,
			Category:       CategoryAccessControl,
			Title:          "Contract metadata missing",
			Description:    "Deployment metadata is nil; runtime rules cannot be validated",
			Recommendation: "Attach a valid ContractMeta record before deployment is accepted",
			Confidence:     100,
		})
		audit.Passed = false
		audit.Score -= 50
		return audit
	}

	// Check code size
	if uint64(len(code)) > sa.policy.MaxCodeSize {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityCritical,
			Category:       CategoryDenialOfService,
			Title:          "Code size exceeds policy limit",
			Description:    fmt.Sprintf("Contract code is %d bytes, exceeds limit of %d", len(code), sa.policy.MaxCodeSize),
			Recommendation: "Reduce contract size by refactoring or splitting logic",
			Confidence:     100,
		})
		audit.Passed = false
		audit.Score -= 50
	}

	// Check runtime is allowed
	runtimeAllowed := false
	for _, allowed := range sa.policy.AllowedRuntimes {
		if allowed == meta.Runtime {
			runtimeAllowed = true
			break
		}
	}
	if !runtimeAllowed {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityCritical,
			Category:       CategoryAccessControl,
			Title:          "Runtime not allowed by policy",
			Description:    fmt.Sprintf("Runtime %s is not in the allowed list", meta.Runtime),
			Recommendation: "Use an approved runtime or update security policy",
			Confidence:     100,
		})
		audit.Passed = false
		audit.Score -= 50
	}

	// WASM-specific checks
	if meta.Runtime == RuntimeWASM && IsWASM(code) {
		sa.auditWASMCode(code, audit)
	}

	// Check ABI version requirement
	if sa.policy.RequireABIVersion && meta.RuntimeVersion == 0 {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityHigh,
			Category:       CategoryAccessControl,
			Title:          "Missing ABI version",
			Description:    "Contract does not specify a runtime version",
			Recommendation: "Set RuntimeVersion in contract metadata",
			Confidence:     90,
		})
		audit.Passed = false
		audit.Score -= 10
	}

	if err := ValidateContractMeta(meta); err != nil {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityHigh,
			Category:       CategoryAccessControl,
			Title:          "Runtime metadata invalid",
			Description:    err.Error(),
			Recommendation: "Use a supported runtime and a valid version field",
			Confidence:     100,
		})
		audit.Passed = false
		audit.Score -= 15
	}

	return audit
}

// auditWASMCode performs WASM-specific security checks
func (sa *SecurityAuditor) auditWASMCode(code []byte, audit *SecurityAudit) {
	// Check for forbidden opcodes
	// This is a simplified check; production would use WASM binary format analysis
	wasmStr := string(code)

	// Check for unbounded loops (opcodes 0x03 and 0x04 for loop/block without bounds)
	if strings.Contains(wasmStr, "loop") {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityHigh,
			Category:       CategoryDenialOfService,
			Title:          "Unbounded loop detected",
			Description:    "Contract contains loop opcode which may cause infinite loops",
			Recommendation: "Add explicit loop bounds or use bounded iteration patterns",
			Confidence:     70,
		})
		audit.Score -= 15
	}

	// Check for potential integer overflows (addition without overflow check)
	if strings.Contains(wasmStr, "i64.add") || strings.Contains(wasmStr, "i32.add") {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityMedium,
			Category:       CategoryIntegerOverflow,
			Title:          "Arithmetic operations detected",
			Description:    "Contract contains arithmetic operations that may overflow",
			Recommendation: "Verify overflow checks are implemented for all arithmetic",
			Confidence:     60,
		})
		audit.Score -= 10
	}

	// Check for potential reentrancy (multiple transfers)
	transferCount := strings.Count(wasmStr, "transfer")
	if transferCount > 1 && sa.policy.ReentrancyProtection {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityHigh,
			Category:       CategoryReentrancy,
			Title:          "Multiple transfers detected",
			Description:    fmt.Sprintf("Contract contains %d transfer calls, potential reentrancy", transferCount),
			Recommendation: "Use checks-effects-interactions pattern and guard state changes",
			Confidence:     65,
		})
		audit.Score -= 15
	}

	// Check memory access patterns
	if strings.Contains(wasmStr, "memory.grow") {
		audit.Issues = append(audit.Issues, SecurityIssue{
			Severity:       SeverityMedium,
			Category:       CategoryDenialOfService,
			Title:          "Dynamic memory growth",
			Description:    "Contract calls memory.grow which may exceed limits",
			Recommendation: "Ensure memory growth is bounded and pre-allocated where possible",
			Confidence:     75,
		})
		audit.Score -= 10
	}
}

// ComplianceChecker verifies contract compliance with upgrade policies
type ComplianceChecker struct {
	policy UpgradePolicy
}

// UpgradePolicy defines rules for contract upgrades
type UpgradePolicy struct {
	// AllowBreakingChanges permits incompatible ABI changes
	AllowBreakingChanges bool

	// RequireDeploymentApproval requires governance approval for deployment
	RequireDeploymentApproval bool

	// MaxUpgradesPerBlock limits upgrades per block
	MaxUpgradesPerBlock uint32

	// VersionIncrement specifies the minimum version increase
	VersionIncrement uint32

	// DeprecationPeriod is the blocks to wait before removing old version
	DeprecationPeriod uint64

	// RequireMigration requires data migration functions for breaking changes
	RequireMigration bool
}

// NewComplianceChecker creates a compliance checker
func NewComplianceChecker(policy UpgradePolicy) *ComplianceChecker {
	return &ComplianceChecker{policy: policy}
}

// CheckUpgrade verifies if an upgrade is compliant
func (cc *ComplianceChecker) CheckUpgrade(oldMeta, newMeta *ContractMeta, oldABI, newABI *ContractABI) []error {
	var errs []error
	if oldMeta == nil || newMeta == nil {
		errs = append(errs, errors.New("upgrade requires both old and new metadata"))
		return errs
	}

	// Check runtime didn't change
	if oldMeta.Runtime != newMeta.Runtime {
		errs = append(errs, fmt.Errorf("runtime change not allowed: %s -> %s", oldMeta.Runtime, newMeta.Runtime))
	}

	// Check version increase
	versionDiff := newMeta.RuntimeVersion - oldMeta.RuntimeVersion
	if versionDiff < cc.policy.VersionIncrement {
		errs = append(errs, fmt.Errorf("version increase too small: %d < %d", versionDiff, cc.policy.VersionIncrement))
	}

	// Check ABI compatibility
	if oldABI != nil && newABI != nil {
		if !areABIsCompatible(oldABI, newABI) {
			if !cc.policy.AllowBreakingChanges {
				errs = append(errs, errors.New("ABI breaking change detected"))
			}
			if cc.policy.RequireMigration {
				errs = append(errs, errors.New("migration function required for breaking changes"))
			}
		}
	}

	return errs
}

// DefaultUpgradePolicy returns a conservative production policy for versioned
// contract upgrades.
func DefaultUpgradePolicy() UpgradePolicy {
	return UpgradePolicy{
		AllowBreakingChanges:      false,
		RequireDeploymentApproval: true,
		MaxUpgradesPerBlock:       1,
		VersionIncrement:          1,
		DeprecationPeriod:         1200,
		RequireMigration:          true,
	}
}

// areABIsCompatible checks if a new ABI is backward compatible.
func areABIsCompatible(oldABI, newABI *ContractABI) bool {
	if oldABI == nil || newABI == nil {
		return false
	}
	oldMethods := make(map[string]ABIMethod, len(oldABI.Methods))
	for _, method := range oldABI.Methods {
		oldMethods[strings.ToLower(method.Name)] = method
	}

	for _, method := range newABI.Methods {
		oldMethod, ok := oldMethods[strings.ToLower(method.Name)]
		if !ok {
			return false // Method removed
		}
		if len(oldMethod.Parameters) != len(method.Parameters) {
			return false
		}
		if len(oldMethod.Returns) != len(method.Returns) {
			return false
		}
		for i := range oldMethod.Parameters {
			if oldMethod.Parameters[i].Type != method.Parameters[i].Type {
				return false
			}
			if oldMethod.Parameters[i].Optional != method.Parameters[i].Optional {
				return false
			}
		}
		for i := range oldMethod.Returns {
			if oldMethod.Returns[i].Type != method.Returns[i].Type {
				return false
			}
		}
	}
	return true
}

// ResourceLimiter enforces resource consumption limits during execution
type ResourceLimiter struct {
	policy      *SecurityPolicy
	startTime   int64
	gasBudget   uint64
	gasUsed     uint64
	memoryUsed  uint64
	storageUsed uint64
	callDepth   uint32
}

// NewResourceLimiter creates a resource limiter
func NewResourceLimiter(policy *SecurityPolicy, gasBudget uint64) *ResourceLimiter {
	if policy == nil {
		policy = DefaultSecurityPolicy()
	}
	return &ResourceLimiter{
		policy:    policy,
		gasBudget: gasBudget,
		gasUsed:   0,
	}
}

// ChargeGas consumes gas from the budget
func (rl *ResourceLimiter) ChargeGas(amount uint64) error {
	maxGas := uint64(math.MaxUint64)
	if amount > maxGas-rl.gasUsed {
		return fmt.Errorf("gas overflow: %d + %d > %d", rl.gasUsed, amount, maxGas)
	}
	if rl.gasUsed+amount > rl.gasBudget {
		return fmt.Errorf("gas limit exceeded: %d + %d > %d", rl.gasUsed, amount, rl.gasBudget)
	}
	rl.gasUsed += amount
	return nil
}

// ChargeMemory tracks memory usage
func (rl *ResourceLimiter) ChargeMemory(bytes uint64) error {
	if rl.memoryUsed+bytes > uint64(rl.policy.MaxMemoryPages)*65536 {
		return fmt.Errorf("memory limit exceeded: %d + %d > %d", rl.memoryUsed, bytes, uint64(rl.policy.MaxMemoryPages)*65536)
	}
	rl.memoryUsed += bytes
	return nil
}

// ChargeStorage tracks storage usage
func (rl *ResourceLimiter) ChargeStorage(bytes uint64) error {
	if rl.storageUsed+bytes > rl.policy.MaxStorageSize {
		return fmt.Errorf("storage limit exceeded: %d + %d > %d", rl.storageUsed, bytes, rl.policy.MaxStorageSize)
	}
	rl.storageUsed += bytes
	return nil
}

// EnterCall increments call depth
func (rl *ResourceLimiter) EnterCall() error {
	if rl.callDepth >= rl.policy.MaxCallDepth {
		return fmt.Errorf("call depth limit exceeded: %d >= %d", rl.callDepth, rl.policy.MaxCallDepth)
	}
	rl.callDepth++
	return nil
}

// ExitCall decrements call depth
func (rl *ResourceLimiter) ExitCall() error {
	if rl.callDepth == 0 {
		return errors.New("call stack underflow")
	}
	rl.callDepth--
	return nil
}

// GetStats returns current resource usage
func (rl *ResourceLimiter) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"gas_used":       rl.gasUsed,
		"gas_budget":     rl.gasBudget,
		"memory_used":    rl.memoryUsed,
		"storage_used":   rl.storageUsed,
		"call_depth":     rl.callDepth,
		"max_call_depth": rl.policy.MaxCallDepth,
	}
}

// InputValidator validates contract input parameters
type InputValidator struct {
	maxStringLength uint32
	maxArrayLength  uint32
}

// NewInputValidator creates an input validator
func NewInputValidator() *InputValidator {
	return &InputValidator{
		maxStringLength: 10_000,
		maxArrayLength:  10_000,
	}
}

// ValidateInput checks if input is safe
func (iv *InputValidator) ValidateInput(args []ABIValue) error {
	for i, arg := range args {
		if err := iv.validateValue(&arg); err != nil {
			return fmt.Errorf("arg[%d]: %w", i, err)
		}
	}
	return nil
}

func (iv *InputValidator) validateValue(v *ABIValue) error {
	if v == nil {
		return errors.New("nil ABI value")
	}
	switch v.Type {
	case ABITypeString:
		s, _ := v.AsString()
		if uint32(len(s)) > iv.maxStringLength {
			return fmt.Errorf("string too long: %d > %d", len(s), iv.maxStringLength)
		}
	case ABITypeBytes:
		b, _ := v.AsBytes()
		if uint32(len(b)) > iv.maxStringLength {
			return fmt.Errorf("bytes too long: %d > %d", len(b), iv.maxStringLength)
		}
	case ABITypeArray:
		items, _ := v.AsArray()
		if uint32(len(items)) > iv.maxArrayLength {
			return fmt.Errorf("array too long: %d > %d", len(items), iv.maxArrayLength)
		}
		for i, item := range items {
			if err := iv.validateValue(&item); err != nil {
				return fmt.Errorf("array[%d]: %w", i, err)
			}
		}
	case ABITypeStruct:
		fields, _ := v.AsStruct()
		for name, field := range fields {
			if err := iv.validateValue(field); err != nil {
				return fmt.Errorf("field[%s]: %w", name, err)
			}
		}
	case ABITypeOptional:
		opt, err := v.AsOptional()
		if err != nil {
			return err
		}
		if opt != nil {
			return iv.validateValue(opt)
		}
	}
	return nil
}
