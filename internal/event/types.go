package event

import "time"

type Event struct {
	Request  *Request  `json:"request"`
	Response *Response `json:"response,omitempty"`
}

type Request struct {
	ID          string            `json:"id"`
	Headers     map[string]string `json:"headers"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Path        string            `json:"path,omitempty"`
	Search      string            `json:"search,omitempty"`
	Body        any               `json:"body,omitempty"`
	RequestedAt time.Time         `json:"requestedAt"`
}

type Response struct {
	Headers     map[string]string `json:"headers"`
	Status      int               `json:"status"`
	StatusText  string            `json:"statusText"`
	Body        any               `json:"body,omitempty"`
	RespondedAt time.Time         `json:"respondedAt"`
	Duration    int               `json:"duration"`
}
