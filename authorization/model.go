package authorization

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/samber/lo"

	pb "github.com/murouse/membrane/pkg/api/murouse/membrane/v1"
)

type Policy struct {
	AllowUnauthenticated bool
	Rule                 *Rule
}

type Rule struct {
	AnyOf mapset.Set[int32]
	AllOf mapset.Set[int32]

	NestedAnyOf []Rule
	NestedAllOf []Rule
}

func PolicyToModel(p *pb.Policy) Policy {
	policy := Policy{
		AllowUnauthenticated: p.AllowUnauthenticated,
		Rule:                 nil,
	}

	if p.Rule != nil {
		policy.Rule = lo.ToPtr(RuleToModel(p.Rule))
	}

	return policy
}

func RuleToModel(r *pb.Rule) Rule {
	conv := func(rs []pb.Role) mapset.Set[int32] {
		return mapset.NewSet(lo.Map(rs, func(r pb.Role, _ int) int32 {
			return int32(r)
		})...)
	}

	return Rule{
		AnyOf:       conv(r.AnyOf),
		AllOf:       conv(r.AllOf),
		NestedAnyOf: RulesToModel(r.NestedAnyOf),
		NestedAllOf: RulesToModel(r.NestedAllOf),
	}
}

func RulesToModel(rs []*pb.Rule) []Rule {
	return lo.Map(rs, func(r *pb.Rule, _ int) Rule {
		return RuleToModel(r)
	})
}

func (r *Rule) Evaluate(roles mapset.Set[int32]) bool {
	if !r.AnyOf.IsEmpty() && !r.AnyOf.ContainsAnyElement(roles) {
		return false
	}

	if !r.AllOf.IsEmpty() && !r.AllOf.IsSubset(roles) {
		return false
	}

	// NestedAnyOf
	nestedAnyOf := false
	for _, rule := range r.NestedAnyOf {
		if rule.Evaluate(roles) {
			nestedAnyOf = true
			break
		}
	}
	if len(r.NestedAnyOf) > 0 && !nestedAnyOf {
		return false
	}

	// NestedAllOf
	for _, rule := range r.NestedAllOf {
		if !rule.Evaluate(roles) {
			return false
		}
	}

	return true
}
