package provider_test

import (
	"context"
	"testing"
	"time"

	"github.com/jasonflaherty/foxhole/pkg/provider"
)

type stubProvider struct {
	id string
}

func (s stubProvider) Metadata() provider.Metadata {
	return provider.Metadata{ID: s.id, Name: s.id}
}
func (s stubProvider) Initialize(ctx context.Context) error { return nil }
func (s stubProvider) Update(ctx context.Context) (*provider.UpdateResult, error) {
	return &provider.UpdateResult{Records: 1, ContentHash: "x", UpdatedAt: time.Now()}, nil
}
func (s stubProvider) Verify(ctx context.Context) error { return nil }
func (s stubProvider) Search(ctx context.Context, q provider.PackageQuery) ([]provider.Result, error) {
	return nil, nil
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	reg := provider.NewRegistry()
	reg.Register(stubProvider{id: "a"})
	reg.Register(stubProvider{id: "b"})
	if len(reg.All()) != 2 {
		t.Fatalf("all = %d", len(reg.All()))
	}
	p, ok := reg.Get("a")
	if !ok || p.Metadata().ID != "a" {
		t.Fatal("get a failed")
	}
	res, err := reg.UpdateAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res["a"].Records != 1 || res["b"].Records != 1 {
		t.Fatalf("results = %#v", res)
	}
}
