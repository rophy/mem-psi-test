package ebpf

import (
	ciliumebpf "github.com/cilium/ebpf"
)

// Objects wraps the generated dentryObjects to export it.
type Objects struct {
	objs dentryObjects
}

// LoadObjects loads the eBPF objects from the embedded bytecode.
func LoadObjects(opts *ciliumebpf.CollectionOptions) (*Objects, error) {
	var objs dentryObjects
	if err := loadDentryObjects(&objs, opts); err != nil {
		return nil, err
	}
	return &Objects{objs: objs}, nil
}

// Close releases all eBPF resources.
func (o *Objects) Close() error {
	return o.objs.Close()
}

// Programs

func (o *Objects) TraceDAlloc() *ciliumebpf.Program      { return o.objs.TraceD_alloc }
func (o *Objects) TraceDAllocPath() *ciliumebpf.Program  { return o.objs.TraceD_allocPath }
func (o *Objects) TraceDInstantiate() *ciliumebpf.Program { return o.objs.TraceD_instantiate }
func (o *Objects) TraceShrinkDcache() *ciliumebpf.Program { return o.objs.TraceShrinkDcache }

// Maps

func (o *Objects) DentryStatsMap() *ciliumebpf.Map { return o.objs.DentryStatsMap }
func (o *Objects) ReclaimCount() *ciliumebpf.Map   { return o.objs.ReclaimCount }
func (o *Objects) TraceConfigMap() *ciliumebpf.Map  { return o.objs.TraceConfigMap }
func (o *Objects) TraceEvents() *ciliumebpf.Map     { return o.objs.TraceEvents }
