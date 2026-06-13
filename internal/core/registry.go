package core

// Collector gathers a category of artifacts into the shared HostModel.
// Collectors must be read-only: they inspect the system, never modify it.
type Collector interface {
	Name() string
	Collect(ctx *Context) error
}

// Detector consumes the populated HostModel and emits findings.
type Detector interface {
	Name() string
	Detect(ctx *Context) ([]Finding, error)
}

var (
	collectors []Collector
	detectors  []Detector
)

// RegisterCollector adds a collector to the global pipeline. Intended to be
// called from collector package init() functions.
func RegisterCollector(c Collector) { collectors = append(collectors, c) }

// RegisterDetector adds a detector to the global pipeline.
func RegisterDetector(d Detector) { detectors = append(detectors, d) }

// Collectors returns the registered collectors.
func Collectors() []Collector { return collectors }

// Detectors returns the registered detectors.
func Detectors() []Detector { return detectors }

// Run executes the full collect -> detect pipeline against ctx. Scoring and
// reporting are handled by the caller so they can pick output formats.
func (c *Context) Run() {
	for _, col := range collectors {
		c.Logger.Printf("collect: %s", col.Name())
		if err := col.Collect(c); err != nil {
			c.Logger.Printf("collector %s failed: %v", col.Name(), err)
		}
	}
	for _, det := range detectors {
		c.Logger.Printf("detect: %s", det.Name())
		fs, err := det.Detect(c)
		if err != nil {
			c.Logger.Printf("detector %s failed: %v", det.Name(), err)
			continue
		}
		for _, f := range fs {
			c.AddFinding(f)
		}
	}
}
