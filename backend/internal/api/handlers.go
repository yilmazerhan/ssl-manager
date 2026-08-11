package api

import (
	"encoding/json"
	"net/http"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
)

type handlers struct {
	certs  certificate.Store
	orders *order.Service
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handlers) listCertificates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.certs.List())
}

func (h *handlers) getCertificate(w http.ResponseWriter, r *http.Request) {
	c, ok := h.certs.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// downloadCertificate returns the latest version's PEM material. The plan
// (section 07/09) requires this to sit behind a certs:export scope and a
// short-lived, MFA-gated download token — neither is enforced here yet.
func (h *handlers) downloadCertificate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.certs.Get(id); !ok {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	versions := h.certs.Versions(id)
	if len(versions) == 0 {
		writeError(w, http.StatusNotFound, "no issued version for this certificate")
		return
	}
	writeJSON(w, http.StatusOK, versions[len(versions)-1])
}

func (h *handlers) certificateHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.certs.Get(id); !ok {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	writeJSON(w, http.StatusOK, h.certs.Versions(id))
}

// renewCertificate is a placeholder for triggering the renewal engine
// (section 06) on demand for a single certificate.
func (h *handlers) renewCertificate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.certs.Get(id); !ok {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	writeError(w, http.StatusNotImplemented, "renewal engine is not wired up yet")
}

func (h *handlers) createOrder(w http.ResponseWriter, r *http.Request) {
	var req order.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	o, err := h.orders.Create(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, o)
}

func (h *handlers) getOrder(w http.ResponseWriter, r *http.Request) {
	o, ok := h.orders.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func (h *handlers) validateOrder(w http.ResponseWriter, r *http.Request) {
	o, err := h.orders.Validate(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
