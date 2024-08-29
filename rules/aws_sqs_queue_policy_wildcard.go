package rules

import (
    "github.com/terraform-linters/tflint-plugin-sdk/hclext"
    "github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AwsSqsQueuePolicyWildcardRule checks for wildcard actions in SQS queue policies
type AwsSqsQueuePolicyWildcardRule struct {
    tflint.DefaultRule
}

// NewAwsSqsQueuePolicyWildcardRule returns a new rule
func NewAwsSqsQueuePolicyWildcardRule() *AwsSqsQueuePolicyWildcardRule {
    return &AwsSqsQueuePolicyWildcardRule{}
}

// Name returns the rule name
func (r *AwsSqsQueuePolicyWildcardRule) Name() string {
    return "aws_sqs_queue_policy_wildcard"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsSqsQueuePolicyWildcardRule) Enabled() bool {
    return true
}

// Severity returns the rule severity
func (r *AwsSqsQueuePolicyWildcardRule) Severity() tflint.Severity {
    return tflint.WARNING
}

// Link returns the rule reference link
func (r *AwsSqsQueuePolicyWildcardRule) Link() string {
    return ""
}

// Check applies the rule to check for wildcard actions
func (r *AwsSqsQueuePolicyWildcardRule) Check(runner tflint.Runner) error {
    resources, err := runner.GetResourceContent("aws_sqs_queue_policy", &hclext.BodySchema{
        Attributes: []hclext.AttributeSchema{
            {Name: "policy"},
        },
    }, nil)
    if err != nil {
        return err
    }

    for _, resource := range resources.Blocks {
        attribute, exists := resource.Body.Attributes["policy"]
        if !exists {
            continue
        }

        var policy string
        err := runner.EvaluateExpr(attribute.Expr, &policy, nil)
        if err != nil {
            return err
        }

        if contains(policy, "sqs:*") || contains(policy, "\"*\"") {
            runner.EmitIssue(
                r,
                "The SQS queue policy contains a wildcard action (sqs:*) or principal (*)",
                attribute.Expr.Range(),
            )
        }
    }

    return nil
}

func contains(s, substr string) bool {
    return len(s) >= len(substr) && s[len(s)-len(substr):] == substr
}