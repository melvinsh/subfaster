package censys

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCensysSource_NoApiKey(t *testing.T) {
	source := &Source{}
	// Don't add any API keys

	ctx := context.Background()
	session := &subscraping.Session{
		Client: http.DefaultClient,
	}

	results := source.Run(ctx, "example.com", session)

	// Collect all results
	var resultCount int
	for range results {
		resultCount++
	}

	// Should be skipped when no API key
	stats := source.Statistics()
	assert.True(t, stats.Skipped, "expected source to be skipped without API key")
	assert.Equal(t, 0, resultCount, "expected no results when skipped")
}

func TestCensysSource_ContextCancellation(t *testing.T) {
	source := &Source{}
	// Add a key with PAT:ORG_ID format
	source.AddApiKeys([]string{"test_pat:test_org_id"})

	ctx := context.Background()
	session := &subscraping.Session{
		Client: http.DefaultClient,
	}

	// Create a context that will be cancelled
	ctxCancellable, cancel := context.WithCancel(ctx)

	results := source.Run(ctxCancellable, "example.com", session)

	// Cancel immediately
	cancel()

	// Should exit quickly without blocking
	done := make(chan struct{})
	go func() {
		for range results {
			// drain
		}
		close(done)
	}()

	select {
	case <-done:
		// Good - completed quickly
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not stop the source in time")
	}
}

func TestCensysSource_Metadata(t *testing.T) {
	source := &Source{}

	assert.Equal(t, "censys", source.Name())
	assert.True(t, source.IsDefault())
	assert.False(t, source.HasRecursiveSupport())
	assert.Equal(t, subscraping.RequiredKey, source.KeyRequirement())
}

func TestCensysSource_AddApiKeys(t *testing.T) {
	t.Run("PAT with OrgID", func(t *testing.T) {
		source := &Source{}
		keys := []string{"pat_token_1:org_id_1", "pat_token_2:org_id_2"}
		source.AddApiKeys(keys)

		require.Len(t, source.apiKeys, 2)
		assert.Equal(t, "pat_token_1", source.apiKeys[0].pat)
		assert.Equal(t, "org_id_1", source.apiKeys[0].orgID)
		assert.Equal(t, "pat_token_2", source.apiKeys[1].pat)
		assert.Equal(t, "org_id_2", source.apiKeys[1].orgID)
	})

	t.Run("PAT without OrgID (free user)", func(t *testing.T) {
		source := &Source{}
		keys := []string{"pat_token_only"}
		source.AddApiKeys(keys)

		require.Len(t, source.apiKeys, 1)
		assert.Equal(t, "pat_token_only", source.apiKeys[0].pat)
		assert.Equal(t, "", source.apiKeys[0].orgID)
	})
}

func TestCensysSource_Statistics(t *testing.T) {
	source := &Source{
		errors:    2,
		results:   10,
		timeTaken: 5 * time.Second,
		skipped:   false,
	}

	stats := source.Statistics()
	assert.Equal(t, 2, stats.Errors)
	assert.Equal(t, 10, stats.Results)
	assert.Equal(t, 5*time.Second, stats.TimeTaken)
	assert.False(t, stats.Skipped)
}
