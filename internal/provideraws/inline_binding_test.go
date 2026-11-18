package provideraws

import (
	"os"
	"path/filepath"
	"testing"
)

// An importer written as a func literal in schema.ResourceImporter, trimmed
// from internal/service/kinesis/stream.go at v6.72.0, resolves like a named
// one: its body and the helpers it calls hold the import's calls. A CRUD key
// of schema.Resource bound to a func literal resolves the same way.
func TestParsePackage_InlineClosureBindings(t *testing.T) {
	src := `package kinesis

// @SDKResource("aws_kinesis_stream", name="Stream")
func resourceStream() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceStreamCreate,
		ReadWithoutTimeout:   resourceStreamRead,
		DeleteWithoutTimeout: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			conn := meta.(*conns.AWSClient).KinesisClient(ctx)
			_, err := conn.DeleteStream(ctx, &kinesis.DeleteStreamInput{})
			if err != nil {
				return nil
			}
			return nil
		},

		Importer: &schema.ResourceImporter{
			StateContext: func(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
				if err := importer.Import(ctx, d, meta); err != nil {
					return nil, err
				}
				conn := meta.(*conns.AWSClient).KinesisClient(ctx)
				output, err := findStreamByName(ctx, conn, d.Id())
				if err != nil {
					return nil, err
				}
				d.Set(names.AttrARN, output.StreamARN)
				return []*schema.ResourceData{d}, nil
			},
		},
	}
}

func resourceStreamCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)
	_, err := conn.CreateStream(ctx, &kinesis.CreateStreamInput{})
	if err != nil {
		return nil
	}
	return nil
}

func resourceStreamRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)
	_, err := findStreamByName(ctx, conn, d.Id())
	if err != nil {
		return nil
	}
	return nil
}

func findStreamByName(ctx context.Context, conn *kinesis.Client, name string) (*types.StreamDescriptionSummary, error) {
	output, err := conn.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{})
	if err != nil {
		return nil, err
	}
	return output.StreamDescriptionSummary, nil
}
`
	pkg, err := ParsePackage(map[string]string{"stream.go": src})
	if err != nil {
		t.Fatal(err)
	}
	actions, _ := pkg.ResourceActions("stream.go", "Stream")
	if got := actionNames(actions, "import"); !equalStrings(got, []string{"kinesis:DescribeStreamSummary"}) {
		t.Errorf("import = %v, want [kinesis:DescribeStreamSummary]", got)
	}
	if got := actionNames(actions, "delete"); !equalStrings(got, []string{"kinesis:DeleteStream"}) {
		t.Errorf("delete = %v, want [kinesis:DeleteStream]", got)
	}
}

// Two resources of one package that each bind an inline importer keep their
// own calls: the synthetic names of the two literals do not collide.
func TestParsePackage_InlineImportersStayApart(t *testing.T) {
	stream := `package kinesis

// @SDKResource("aws_kinesis_stream", name="Stream")
func resourceStream() *schema.Resource {
	return &schema.Resource{
		Importer: &schema.ResourceImporter{
			StateContext: func(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
				meta.(*conns.AWSClient).KinesisClient(ctx).DescribeStreamSummary(ctx, nil)
				return nil, nil
			},
		},
	}
}
`
	consumer := `package kinesis

// @SDKResource("aws_kinesis_stream_consumer", name="Stream Consumer")
func resourceStreamConsumer() *schema.Resource {
	return &schema.Resource{
		Importer: &schema.ResourceImporter{
			StateContext: func(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
				meta.(*conns.AWSClient).KinesisClient(ctx).DescribeStreamConsumer(ctx, nil)
				return nil, nil
			},
		},
	}
}
`
	pkg, err := ParsePackage(map[string]string{"stream.go": stream, "stream_consumer.go": consumer})
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		"stream.go":          "kinesis:DescribeStreamSummary",
		"stream_consumer.go": "kinesis:DescribeStreamConsumer",
	} {
		actions, _ := pkg.ResourceActions(file, "")
		if got := actionNames(actions, "import"); !equalStrings(got, []string{want}) {
			t.Errorf("%s: import = %v, want [%s]", file, got, want)
		}
	}
}

// The OpsWorks layers build their schema.Resource in a method of a shared
// layer type, trimmed from internal/service/opsworks/layers.go at v5.100.0,
// with func literals that call the method's receiver. A literal in a method
// needs its receiver, which the index can't bind, so it stays unresolved and
// layers.go doesn't become a resource of its own.
func TestSourceProvider_InlineBindingInMethodStaysUnresolved(t *testing.T) {
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", "opsworks")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `package opsworks

func (lt *opsworksLayerType) resourceSchema() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			return lt.Create(ctx, d, meta)
		},
		ReadWithoutTimeout: func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			return lt.Read(ctx, d, meta)
		},
	}
}

func (lt *opsworksLayerType) Create(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).OpsWorksClient(ctx)
	conn.CreateLayer(ctx, nil)
	return nil
}

func (lt *opsworksLayerType) Read(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).OpsWorksClient(ctx)
	conn.DescribeLayers(ctx, nil)
	return nil
}
`
	if err := os.WriteFile(filepath.Join(svcDir, "layers.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSourceProviderWithPath(dir).Resolve("aws_opsworks_layers"); err == nil {
		t.Error("Resolve succeeded for layers.go, whose schema.Resource sits in a method, want not found")
	}
}
