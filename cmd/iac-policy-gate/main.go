package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Zaynereo/iac-policy-gate/internal/exitcode"
	"github.com/Zaynereo/iac-policy-gate/internal/output"
	"github.com/Zaynereo/iac-policy-gate/internal/plan"
	"github.com/Zaynereo/iac-policy-gate/internal/policy"
)

func main() {
	os.Exit(run())
}

func run() int {
	planPath := flag.String("plan", "-", "Path to Terraform/OpenTofu plan JSON (- for stdin)")
	jsonOut := flag.Bool("json", false, "Emit findings as JSON")
	label := flag.String("label", "", "Optional label included in output (e.g. synthetic-fixture name)")
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", flag.Args())
		return exitcode.Usage
	}

	doc, err := plan.ReadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plan error: %v\n", err)
		return exitcode.PlanError
	}

	rep := policy.Evaluate(doc)
	rep.PlanLabel = *label

	if *jsonOut {
		data, err := rep.JSONBytes()
		if err != nil {
			fmt.Fprintf(os.Stderr, "internal error: %v\n", err)
			return exitcode.Internal
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(output.WriteText(rep))
	}

	if !rep.Passed {
		return exitcode.PolicyFail
	}
	return exitcode.OK
}
