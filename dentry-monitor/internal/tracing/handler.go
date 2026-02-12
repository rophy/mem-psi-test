package tracing

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Handler provides HTTP handlers for the tracing API.
type Handler struct {
	consumer *Consumer
}

// NewHandler creates a tracing HTTP handler.
func NewHandler(consumer *Consumer) *Handler {
	return &Handler{consumer: consumer}
}

// RegisterRoutes registers tracing endpoints on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/traces", h.handleTraces)
	mux.HandleFunc("/traces/config", h.handleConfig)
}

func (h *Handler) handleTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	filter := EventFilter{
		Pod:           q.Get("pod"),
		Namespace:     q.Get("namespace"),
		PathSubstring: q.Get("path"),
	}

	if limitStr := q.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err == nil && limit > 0 {
			filter.Limit = limit
		}
	} else {
		filter.Limit = 100 // default
	}

	if sinceStr := q.Get("since"); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err == nil {
			filter.Since = t
		}
	}

	resp := h.consumer.GetEvents(filter)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := h.consumer.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		var cfg TraceConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := h.consumer.SetConfig(cfg); err != nil {
			http.Error(w, "failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
