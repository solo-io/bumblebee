// Code generated by skv2. DO NOT EDIT.

// This file contains generated Deepcopy methods for probes.bumblebee.io/v1alpha1 resources

package v1alpha1

import (
	"encoding/json"

	runtime "k8s.io/apimachinery/pkg/runtime"
)

// Generated Deepcopy methods for Probe

func (in *Probe) DeepCopyInto(out *Probe) {
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)

	// deepcopy spec
	b, _ := json.Marshal(in.Spec)
	_ = json.Unmarshal(b, &out.Spec)

	return
}

func (in *Probe) DeepCopy() *Probe {
	if in == nil {
		return nil
	}
	out := new(Probe)
	in.DeepCopyInto(out)
	return out
}

func (in *Probe) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *ProbeList) DeepCopyInto(out *ProbeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Probe, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

func (in *ProbeList) DeepCopy() *ProbeList {
	if in == nil {
		return nil
	}
	out := new(ProbeList)
	in.DeepCopyInto(out)
	return out
}

func (in *ProbeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}