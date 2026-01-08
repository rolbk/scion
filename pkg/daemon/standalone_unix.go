//go:build unix && !darwin

package daemon

// DefaultConfigDir is the default directory for SCION configuration.
const DefaultConfigDir = "/etc/scion"
