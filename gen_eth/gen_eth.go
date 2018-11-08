/*
A CLI tool that reads Solidity contracts as *.sol files and outputs ABI
definitions as *.go code. Requires a Solidity compiler; see the documentation at
https://solidity.readthedocs.io

Installation:

	go get -u github.com/purelabio/eth/gen_eth

Example usage:

	gen_eth -help
	gen_eth -out gen_contracts.go sol/Test.sol:Test

To use with "go generate", include a "go:generate" comment in your source code:

	//go:generate gen_eth -out gen_contracts.go sol/Test.sol:Test

The generated file contains ABI definitions and contract code in various
formats: Abi data structure, JSON ABI string, contract code as bytes, contract
code as hex-encoded string. The solc compiler is invoked with "--optimize".

The generated code doesn't contain any function calls and has no impact on the
program startup.

Currently, this doesn't attempt to generate callable contract methods or event
definitions. Such functionality may be added in the future, if there's demand.
*/
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/template"

	"github.com/mitranim/repr"
	"github.com/pkg/errors"
	"github.com/purelabio/eth"
)

var (
	flagSolc = flag.String("solc", "solc", "Solidity compiler; can be overridden with the SOLC environment variable")
	flagOut  = flag.String("out", "", "output path for the generated Go file (required)")
	flagPkg  = flag.String("pkg", "main", "package name for the generated code")
	flagSelf = flag.Bool("self", false, "generate without imports or package prefixes")
)

var codeTemplate = template.Must(template.New("").
	Funcs(template.FuncMap{
		"pkgPrefix": pkgPrefix,
		"repr":      reprString,
		"reprBytes": func(input []byte) string { return reprString(input) },
	}).
	Parse(`
{{range .}}

var {{.ContractName}}Abi = {{.Abi | repr}}

const {{.ContractName}}AbiJson = ` + "`" + `{{.AbiJson}}` + "`" + `

var {{.ContractName}}Code = {{.Code | reprBytes}}

const {{.ContractName}}CodeHex = ` + "`" + `{{.Code.String}}` + "`" + `

{{end}}
`))

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	execName := os.Args[0]

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage of %v:

	%v <flags> <specs ...>

Specs must have the form "filePath:contractName". Examples:

	%v -out=gen_contracts.go sol/Test.sol:Test
	%v -out=gen_contracts.go sol/file0.sol:A sol/file0.sol:B sol/file1.sol:C

`, execName, execName, execName, execName)
		flag.PrintDefaults()
		flag.CommandLine.Output().Write([]byte("\n"))
	}

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	flag.Parse()

	if os.Getenv("SOLC") != "" {
		*flagSolc = os.Getenv("SOLC")
	}

	if *flagOut == "" {
		return errors.New(`must specify "-out": output path for the generated Go file`)
	}

	specs := flag.Args()
	if len(specs) == 0 {
		return errors.New(`must specify at least one contract, in the form "<filePath>:<contractName>"`)
	}

	// Extract file paths from <filePath>:<contractName> specs
	filePaths := []string{}
	for _, spec := range specs {
		pair := strings.Split(spec, ":")
		if len(pair) < 2 {
			return errors.Errorf(`contract specs must have the form "<filePath>:<contractName>", got %q`, spec)
		}
		filePaths = append(filePaths, pair[0])
	}

	solcArgs := append([]string{"--combined-json=abi,bin", "--optimize"}, filePaths...)
	cmd := exec.Command(*flagSolc, solcArgs...)

	var buf bytes.Buffer
	cmd.Stdin = os.Stdin
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return errors.Wrap(err, "failed to invoke solc")
	}

	defs, err := eth.ReadContractDefs(&buf)
	if err != nil {
		return errors.Wrap(err, "failed to decode ABI output from solc")
	}

	// Pick the specified contracts, validating their presence.
	filteredDefs := map[string]eth.ContractDef{}
	for _, spec := range specs {
		def, ok := defs[spec]
		if !ok {
			return errors.Errorf("contract %q is missing from the solc output; found contracts: %q",
				spec, sortedDefNames(defs))
		}
		filteredDefs[spec] = def
	}
	defs = filteredDefs

	for key, def := range defs {
		def.AbiJson, err = prettyJson(def.AbiJson)
		if err != nil {
			panic(err)
		}
		defs[key] = def
	}

	buf.Reset()
	fmt.Fprintf(&buf, "package %v\n", *flagPkg)
	if !*flagSelf {
		buf.WriteString(`import "github.com/purelabio/eth"` + "\n")
	}

	err = codeTemplate.Execute(&buf, defs)
	if err != nil {
		panic(err)
	}

	source, err := format.Source(buf.Bytes())
	if err != nil {
		panic(err)
	}

	const readWriteMode = os.FileMode(0600)
	err = ioutil.WriteFile(*flagOut, source, readWriteMode)
	if err != nil {
		return errors.Wrapf(err, "failed to write %q", *flagOut)
	}
	return nil
}

func sortedDefNames(defs map[string]eth.ContractDef) []string {
	var names []string
	for name := range defs {
		names = append(names, name)
	}
	sort.Slice(names, func(a, b int) bool {
		return names[a] < names[b]
	})
	return names
}

func prettyJson(input string) (string, error) {
	var val interface{}
	err := json.Unmarshal([]byte(input), &val)
	pretty, err := json.MarshalIndent(val, "", "\t")
	return string(pretty), err
}

func pkgPrefix() string {
	if *flagSelf {
		return ""
	}
	return "eth."
}

func reprString(val interface{}) string {
	if *flagSelf {
		return repr.StringC(val, repr.Config{
			PackageMap: map[string]string{
				"github.com/purelabio/eth": "",
			},
		})
	}
	return repr.String(val)
}
