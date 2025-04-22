package main

import (
	"context"
	"log/slog"

	"github.com/songgao/water"
)

// copyToDevice copies packets from a channel to a tun device
func copyToDevice(ctx context.Context, dst *water.Interface, src chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-src:
			_, err := dst.Write(packet)
			if err != nil {
				slog.Error("error writing to tun: dropping and continuing...", "bytes", len(packet), "err", err)
			}

			slog.Debug("sending bytes to subprocess", "bytes", len(packet))
		}
	}
}
