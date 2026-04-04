package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the API group and version for kontxt types.
	GroupVersion = schema.GroupVersion{Group: "kontxt.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add Go types to the GroupVersionResource scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&TxTokenConfig{},
		&TxTokenConfigList{},
		&TransactionType{},
		&TransactionTypeList{},
		&ServiceTokenRequirement{},
		&ServiceTokenRequirementList{},
		&TokenPolicy{},
		&TokenPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
