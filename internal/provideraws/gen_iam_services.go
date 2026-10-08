//go:build ignore

// gen_iam_services writes iam_services_gen.go and testdata/iam_prefixes.txt.
// It joins two sources:
//
//   - a terraform-provider-aws checkout, for the SDK packages the provider
//     imports, the names it imports them under, its AWSClient accessors, and
//     names/data/names_data.hcl, which names each package's AWS CLI command;
//   - the AWS service reference (https://servicereference.us-east-1.amazonaws.com/),
//     the machine-readable form of the Service Authorization Reference. Its
//     operations list the Boto3 client that makes each call and the IAM
//     actions the call needs.
//
// A package's IAM prefix is the service most of its client's operations
// authorize. An operation whose name is not an IAM action of that prefix gets
// a rename row to the action it needs, e.g. s3 HeadObject → s3:GetObject.
//
// Run it from the repository root when the provider ref changes:
//
//	go run internal/provideraws/gen_iam_services.go -provider <checkout>
//
// Pass -ref <dir> to read the service reference from a directory holding
// index.json and one <prefix>.json per service, instead of fetching it.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const referenceIndex = "https://servicereference.us-east-1.amazonaws.com/"

// boto3Overrides names the Boto3 client of a package where neither the AWS CLI
// command nor the package name, with or without dashes, matches it.
var boto3Overrides = map[string]string{
	"configservice": "config", // CLI command configservice, Boto3 client config
	"simpledb":      "sdb",    // AWS SDK for Go v1 package
}

// prefixOverrides gives the IAM prefix of an accessor or package that the
// service reference cannot decide.
var prefixOverrides = map[string]string{
	// S3ExpressClient returns an *s3.Client, but it talks to directory
	// buckets, which authorize under s3express.
	"S3ExpressClient": "s3express",
}

// retiredPrefixes are IAM prefixes of services the provider still imports but
// the service reference no longer lists, because AWS retired the service.
var retiredPrefixes = map[string]string{
	"evidently": "evidently", // CloudWatch Evidently
	"iotevents": "iotevents", // AWS IoT Events
}

type reference struct {
	Name       string
	Actions    []struct{ Name string }
	Operations []struct {
		Name              string
		AuthorizedActions []struct{ Name, Service string }
		SDK               []struct{ Name, Package string }
	}
}

func main() {
	provider := flag.String("provider", "", "terraform-provider-aws checkout")
	refDir := flag.String("ref", "", "directory with the service reference JSON (fetched when empty)")
	out := flag.String("out", "internal/provideraws", "output package directory")
	flag.Parse()
	if *provider == "" {
		log.Fatal("-provider is required")
	}

	refs := loadReference(*refDir)
	pkgs, aliases := sdkImports(*provider)
	cli := cliCommands(filepath.Join(*provider, "names", "data", "names_data.hcl"))
	accessors := clientAccessors(filepath.Join(*provider, "internal", "conns"))

	actions := map[string]map[string]bool{} // prefix → its IAM actions
	prefixes := []string{}
	for _, r := range refs {
		prefixes = append(prefixes, r.Name)
		set := map[string]bool{}
		for _, a := range r.Actions {
			set[a.Name] = true
		}
		actions[r.Name] = set
	}
	sort.Strings(prefixes)

	// votes counts, per Boto3 client, the services its operations authorize,
	// and homes how many of its operations each service's page lists.
	votes := map[string]map[string]int{}
	homes := map[string]map[string]int{}
	for _, r := range refs {
		for _, op := range r.Operations {
			services := map[string]bool{}
			for _, a := range op.AuthorizedActions {
				services[a.Service] = true
			}
			for _, sdk := range op.SDK {
				if sdk.Package != "Boto3" {
					continue
				}
				if votes[sdk.Name] == nil {
					votes[sdk.Name] = map[string]int{}
					homes[sdk.Name] = map[string]int{}
				}
				homes[sdk.Name][r.Name]++
				for s := range services {
					votes[sdk.Name][s]++
				}
			}
		}
	}
	dashless := map[string]string{}
	for b := range votes {
		dashless[strings.ReplaceAll(b, "-", "")] = b
	}

	pkgPrefix := map[string]string{}
	pkgBoto3 := map[string]string{}
	for _, pkg := range pkgs {
		if p, ok := retiredPrefixes[pkg]; ok {
			pkgPrefix[pkg] = p
			continue
		}
		b := boto3Client(pkg, cli[pkg], votes, dashless)
		if b != "" {
			pkgBoto3[pkg] = b
			pkgPrefix[pkg] = topVote(b, votes[b], homes[b])
			continue
		}
		// The reference lists some older services without operations: take
		// the prefix that the CLI command or package name spells.
		for _, name := range []string{cli[pkg], pkg} {
			if _, ok := actions[name]; ok {
				pkgPrefix[pkg] = name
				break
			}
		}
		if pkgPrefix[pkg] == "" {
			log.Fatalf("no IAM prefix for SDK package %s (CLI command %q)", pkg, cli[pkg])
		}
	}

	// An import alias resolves to its package's prefix, unless it shadows a
	// package with another prefix.
	for alias, pkg := range aliases {
		if p, ok := pkgPrefix[alias]; ok {
			if p != pkgPrefix[pkg] {
				log.Fatalf("import alias %s of %s shadows package %s", alias, pkg, alias)
			}
			continue
		}
		pkgPrefix[alias] = pkgPrefix[pkg]
	}

	accessorPrefix := map[string]string{}
	for acc, pkg := range accessors {
		if p, ok := prefixOverrides[acc]; ok {
			accessorPrefix[acc] = p
			continue
		}
		p, ok := pkgPrefix[pkg]
		if !ok {
			log.Fatalf("accessor %s returns a client of unmapped package %s", acc, pkg)
		}
		accessorPrefix[acc] = p
	}

	renames := operationRenames(refs, pkgBoto3, pkgPrefix, actions)

	writeGo(filepath.Join(*out, "iam_services_gen.go"), pkgPrefix, accessorPrefix, renames)
	var golden bytes.Buffer
	golden.WriteString("# IAM service prefixes from the AWS service reference, one per line.\n")
	golden.WriteString("# Generated by gen_iam_services.go; do not edit.\n")
	for _, p := range prefixes {
		golden.WriteString(p + "\n")
	}
	if err := os.WriteFile(filepath.Join(*out, "testdata", "iam_prefixes.txt"), golden.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}

// boto3Client returns the Boto3 client name of an SDK package: an override,
// the CLI command, or the package name, matched with or without dashes.
func boto3Client(pkg, cli string, votes map[string]map[string]int, dashless map[string]string) string {
	if b, ok := boto3Overrides[pkg]; ok {
		return b
	}
	for _, name := range []string{cli, pkg} {
		if name == "" {
			continue
		}
		if _, ok := votes[name]; ok {
			return name
		}
		if b, ok := dashless[strings.ReplaceAll(name, "-", "")]; ok {
			return b
		}
	}
	return ""
}

// topVote returns the service the most operations of a Boto3 client
// authorize. On a tie, the service whose page lists more of the operations
// wins: budgets operations authorize both aws-portal and budgets actions, and
// the budgets page lists them. A client whose operations list no actions
// (codeartifact, sdb) takes the page that lists them.
func topVote(client string, votes, homes map[string]int) string {
	if len(votes) == 0 {
		votes = homes
	}
	best := ""
	for s, n := range votes {
		switch {
		case best == "", n > votes[best]:
			best = s
		case n == votes[best] && (homes[s] > homes[best] || homes[s] == homes[best] && s < best):
			best = s
		}
	}
	for s, n := range votes {
		if s != best && n == votes[best] && homes[s] == homes[best] {
			log.Printf("Boto3 client %s: %s and %s tie; chose %s", client, s, best, best)
		}
	}
	return best
}

// operationRenames returns, per IAM prefix, the operations whose name is not
// an IAM action of that prefix, mapped to the action of that prefix they
// need. When an operation needs several, better picks one.
func operationRenames(refs []reference, pkgBoto3, pkgPrefix map[string]string, actions map[string]map[string]bool) map[string]map[string]string {
	boto3Prefix := map[string]string{}
	for pkg, b := range pkgBoto3 {
		boto3Prefix[b] = pkgPrefix[pkg]
	}
	renames := map[string]map[string]string{}
	conflicts := map[string]bool{}
	for _, r := range refs {
		for _, op := range r.Operations {
			for _, sdk := range op.SDK {
				prefix, ok := boto3Prefix[sdk.Name]
				if sdk.Package != "Boto3" || !ok || actions[prefix][op.Name] {
					continue
				}
				best := ""
				for _, a := range op.AuthorizedActions {
					if a.Service != prefix {
						continue
					}
					if best == "" || better(op.Name, a.Name, best) {
						best = a.Name
					}
				}
				// An operation that needs only a tagging action of its
				// service names no permission of its own to rename to.
				if best == "" || isTagging(op.Name, best) {
					continue
				}
				key := prefix + ":" + op.Name
				if renames[prefix] == nil {
					renames[prefix] = map[string]string{}
				}
				if prev, ok := renames[prefix][op.Name]; ok && prev != best {
					conflicts[key] = true
				}
				renames[prefix][op.Name] = best
			}
		}
	}
	for key := range conflicts {
		prefix, op, _ := strings.Cut(key, ":")
		log.Printf("dropping %s: the service reference maps it to more than one action", key)
		delete(renames[prefix], op)
	}
	return renames
}

// better reports whether action a is a closer match for operation op than b.
// An action that only tags what the operation creates loses to any other. Then
// the action that shares more words with the operation wins (DeleteObjects →
// DeleteObject, HeadObject → GetObject), then the shorter name, which is
// usually the base permission rather than one for an optional parameter
// (CreateMultipartUpload → PutObject, not PutObjectLegalHold).
func better(op, a, b string) bool {
	if ta, tb := isTagging(op, a), isTagging(op, b); ta != tb {
		return tb
	}
	sa, sb := affinity(op, a), affinity(op, b)
	if sa != sb {
		return sa > sb
	}
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// isTagging reports whether action tags resources while op does not.
func isTagging(op, action string) bool {
	tagging := func(s string) bool {
		return strings.Contains(s, "Tag")
	}
	return tagging(action) && !tagging(op)
}

// httpVerbs are the IAM actions of API Gateway, keyed by the first word of
// the operations that use them.
var httpVerbs = map[string]string{
	"Create": "POST",
	"Delete": "DELETE",
	"Get":    "GET",
	"Import": "PUT",
	"Put":    "PUT",
	"Update": "PATCH",
}

// affinity counts the words, singular or plural, that op and action share.
// An HTTP verb action matches the operation verb it stands for.
func affinity(op, action string) int {
	opWords := words(op)
	if len(opWords) > 0 && httpVerbs[opWords[0]] == action {
		return len(opWords)
	}
	have := map[string]bool{}
	for _, w := range opWords {
		have[strings.TrimSuffix(w, "s")] = true
	}
	n := 0
	for _, w := range words(action) {
		if have[strings.TrimSuffix(w, "s")] {
			n++
		}
	}
	return n
}

// words splits a PascalCase name into words: "ListObjectsV2" → List, Objects, V2.
func words(name string) []string {
	var out []string
	start := 0
	for i := 1; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' && name[i-1] >= 'a' && name[i-1] <= 'z' {
			out = append(out, name[start:i])
			start = i
		}
	}
	return append(out, name[start:])
}

var (
	importRE   = regexp.MustCompile(`(?m)^\s*(?:([A-Za-z0-9_]+)\s+)?"github.com/aws/aws-sdk-go(?:-v2)?/service/([a-z0-9]+)"`)
	accessorRE = regexp.MustCompile(`func \(c \*AWSClient\) ([A-Za-z0-9]+Client)\(ctx context\.Context\) \*([a-z0-9]+)\.Client`)
	serviceRE  = regexp.MustCompile(`(?ms)^service "([^"]+)" \{(.*?)^\}`)
	v2PkgRE    = regexp.MustCompile(`v2_package\s*=\s*"([^"]+)"`)
	v1PkgRE    = regexp.MustCompile(`v1_package\s*=\s*"([^"]+)"`)
	cliRE      = regexp.MustCompile(`aws_cli_v2_command\s*=\s*"([^"]+)"`)
)

// sdkImports returns the AWS SDK service packages the provider imports, and
// the aliases it imports some of them under.
func sdkImports(provider string) ([]string, map[string]string) {
	seen := map[string]bool{}
	aliases := map[string]string{}
	err := filepath.WalkDir(filepath.Join(provider, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range importRE.FindAllSubmatch(src, -1) {
			pkg := string(m[2])
			seen[pkg] = true
			if alias := string(m[1]); alias != "" && alias != "_" && alias != pkg {
				aliases[alias] = pkg
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	var pkgs []string
	for p := range seen {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	return pkgs, aliases
}

// cliCommands maps SDK package names to AWS CLI commands, read from the
// provider's names data. The service label stands in for a missing value.
func cliCommands(path string) map[string]string {
	src, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	out := map[string]string{}
	for _, m := range serviceRE.FindAllSubmatch(src, -1) {
		label, body := string(m[1]), m[2]
		cli := label
		if c := cliRE.FindSubmatch(body); c != nil {
			cli = string(c[1])
		}
		out[label] = cli
		for _, re := range []*regexp.Regexp{v2PkgRE, v1PkgRE} {
			if p := re.FindSubmatch(body); p != nil {
				out[string(p[1])] = cli
			}
		}
	}
	return out
}

// clientAccessors maps each AWSClient accessor to the SDK package of the
// client it returns.
func clientAccessors(dir string) map[string]string {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		log.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		for _, m := range accessorRE.FindAllSubmatch(src, -1) {
			out[string(m[1])] = string(m[2])
		}
	}
	if len(out) == 0 {
		log.Fatalf("no AWSClient accessors in %s", dir)
	}
	return out
}

// loadReference reads every service of the service reference, from dir or
// from the network.
func loadReference(dir string) []reference {
	var index []struct{ Service, URL string }
	if err := json.Unmarshal(read(dir, "index.json", referenceIndex), &index); err != nil {
		log.Fatal(err)
	}
	refs := make([]reference, len(index))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, e := range index {
		wg.Add(1)
		go func(i int, service, url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := json.Unmarshal(read(dir, service+".json", url), &refs[i]); err != nil {
				log.Fatalf("%s: %v", service, err)
			}
		}(i, e.Service, e.URL)
	}
	wg.Wait()
	return refs
}

func read(dir, name, url string) []byte {
	if dir != "" {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			log.Fatal(err)
		}
		return b
	}
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func writeGo(path string, pkgPrefix, accessorPrefix map[string]string, renames map[string]map[string]string) {
	var b bytes.Buffer
	b.WriteString("// Code generated by gen_iam_services.go; DO NOT EDIT.\n\n")
	b.WriteString("// The tables below join the SDK packages and AWSClient accessors of a\n")
	b.WriteString("// terraform-provider-aws checkout with the AWS service reference\n")
	b.WriteString("// (" + referenceIndex + "). To refresh them, run\n")
	b.WriteString("// go run internal/provideraws/gen_iam_services.go -provider <checkout>.\n\n")
	b.WriteString("package provideraws\n\n")

	b.WriteString("// sdkPackageIAMPrefixes maps AWS SDK service package names, and the aliases\n")
	b.WriteString("// the provider imports them under, to IAM service prefixes.\n")
	b.WriteString("var sdkPackageIAMPrefixes = map[string]string{\n")
	writeMap(&b, pkgPrefix)
	b.WriteString("}\n\n")

	b.WriteString("// clientAccessorIAMPrefixes maps AWSClient accessor methods to the IAM\n")
	b.WriteString("// service prefix of the client they return.\n")
	b.WriteString("var clientAccessorIAMPrefixes = map[string]string{\n")
	writeMap(&b, accessorPrefix)
	b.WriteString("}\n\n")

	b.WriteString("// retiredIAMPrefixes are prefixes the service reference no longer lists,\n")
	b.WriteString("// because AWS retired the service.\n")
	b.WriteString("var retiredIAMPrefixes = map[string]bool{\n")
	for _, k := range sortedKeys(retiredPrefixes) {
		fmt.Fprintf(&b, "%q: true,\n", k)
	}
	b.WriteString("}\n\n")

	b.WriteString("// sdkOperationActions maps, per IAM prefix, SDK operations that are not\n")
	b.WriteString("// IAM actions to the IAM action they need, e.g. s3 HeadObject → GetObject.\n")
	b.WriteString("var sdkOperationActions = map[string]map[string]string{\n")
	prefixes := make([]string, 0, len(renames))
	for p := range renames {
		if len(renames[p]) > 0 {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		fmt.Fprintf(&b, "%q: {\n", p)
		writeMap(&b, renames[p])
		b.WriteString("},\n")
	}
	b.WriteString("}\n")

	src, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, src, 0o644); err != nil {
		log.Fatal(err)
	}
}

func writeMap(b *bytes.Buffer, m map[string]string) {
	for _, k := range sortedKeys(m) {
		fmt.Fprintf(b, "%q: %q,\n", k, m[k])
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
