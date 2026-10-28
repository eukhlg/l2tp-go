package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Two waiting batches at each boundary bound memory independently of traffic
// and flush latency. A blocked flush eventually stops socket reads; the server
// never drops a successfully received datagram to make queue space.
const receivePipelineQueueSize = 2

type receivedBatch struct {
	batch *readBatch
	count int
	err   error
}
type processedBatch struct {
	batch *readBatch
}

// Envelopes in flight: two queued at each boundary plus one in each stage.
const receivePipelineBatches = 2*receivePipelineQueueSize + 3

func (s *Server) servePipeline(parent context.Context, size int, tick time.Duration, conn BatchPacketConn, batched bool) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var mu sync.Mutex
	var failure error
	fail := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if failure == nil {
			failure = err
		}
		mu.Unlock()
		cancel()
	}
	// Wake both reads and synchronous control writes on cancellation or failure.
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		<-ctx.Done()
		_ = s.Conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		_ = s.Conn.SetReadDeadline(time.Now())
	}()
	defer func() { cancel(); <-watcherDone }()
	pool := s.newReadBatchPool(ctx, size, receivePipelineBatches)
	defer pool.close()
	received := make(chan receivedBatch, receivePipelineQueueSize)
	processed := make(chan processedBatch, receivePipelineQueueSize)
	receiveDone, flushDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(receiveDone)
		defer close(received)
		for ctx.Err() == nil {
			// Set deadlines before checking cancellation again: otherwise this could
			// overwrite the watcher's immediate deadline and strand shutdown in Read.
			if err := s.Conn.SetReadDeadline(time.Now().Add(tick)); err != nil {
				fail(err)
				return
			}
			if ctx.Err() != nil {
				return
			}
			b, err := pool.acquire()
			if err != nil {
				if ctx.Err() == nil {
					fail(err)
				}
				return
			}
			n, readErr := b.read(s.Conn, conn, batched)
			if n < 0 || n > len(b.messages) {
				pool.recycle(b)
				fail(io.ErrUnexpectedEOF)
				return
			}
			terminal := false
			if readErr != nil {
				var ne net.Error
				terminal = !errors.As(readErr, &ne) || !ne.Timeout()
			} else if n == 0 {
				readErr = io.ErrNoProgress
				terminal = true
			}
			select {
			case received <- receivedBatch{b, n, readErr}:
			case <-ctx.Done():
				pool.recycle(b)
				return
			}
			if terminal {
				return
			}
		}
	}()
	go func() {
		defer close(flushDone)
		for b := range processed {
			// Even partial/error batches must flush their retained views before release.
			err := b.batch.flush()
			pool.recycle(b.batch)
			if err != nil {
				fail(err)
			}
		}
	}()
	var readFailure error
	for b := range received {
		if ctx.Err() != nil {
			pool.recycle(b.batch)
			continue
		}
		err := s.processReadBatch(b.batch, b.count)
		// Ownership is transferred even on partial dispatch failure. Flush is the
		// only consumer that recycles processed buffers; processing never reuses them.
		processed <- processedBatch{b.batch}
		if err != nil {
			fail(err)
			continue
		}
		if b.err != nil {
			var ne net.Error
			if !errors.As(b.err, &ne) || !ne.Timeout() {
				readFailure = b.err
				continue
			}
		}
		if err := s.retransmit(ctx); err != nil {
			fail(err)
		}
	}
	<-receiveDone
	close(processed)
	<-flushDone
	if parent.Err() != nil {
		return s.cancelShutdown(parent)
	}
	mu.Lock()
	err := failure
	mu.Unlock()
	if err != nil {
		return err
	}
	return readFailure
}
