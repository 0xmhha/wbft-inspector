// Package e2e runs the inspector end to end against the wbft simulator and,
// when a wbft-spec checkout is given, against the wbft vector adapter.
//
// It is a separate module so that the inspector module itself does not
// depend on wbft: the inspector decides from what implementations write,
// not from their code. The wbft version is pinned in go.mod.
package e2e
