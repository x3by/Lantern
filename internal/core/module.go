package core

import "context"

type Module interface {
	Name() string

	HasListener() bool
	HasPoisoner() bool

	StartListener(ctx context.Context, cfg Config) error
	StartPoisoner(ctx context.Context, cfg Config) error
}
