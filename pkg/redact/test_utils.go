package redact

import (
	"github.com/supergoodsystems/supergood-go/pkg/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/pkg/remote-config"
)

func CreateRemoteConfig(redactAll bool) *remoteconfig.RemoteConfig {
	config := remoteconfig.New(remoteconfig.RemoteConfigOpts{
		HandleError: func(error) {},
		RedactAll:   redactAll,
	})
	return &config
}

func CreateEvents() []*event.Event {
	events := []*event.Event{}
	event := &event.Event{
		Request: &event.Request{
			URL:  "test.com/test-endpoint",
			Path: "/test-endpoint",
			Body: map[string]any{
				"key":      "value",
				"keyInt":   1,
				"keyFloat": 1.1,
				"nested": map[string]any{
					"key": "value",
				},
				"array": []string{"item1", "item2"},
				"arrayOfObj": []map[string]any{
					{
						"field1": "value1",
						"field2": "value2",
					},
					{
						"field1": "value3",
						"field2": "value4",
					},
				},
			},
			Headers: map[string]string{
				"key": "value",
			},
		},
		Response: &event.Response{
			Body: map[string]any{
				"key":      "value",
				"keyInt":   1,
				"keyFloat": 1.1,
				"nested": map[string]any{
					"key": "value",
				},
			},
		},
		MetaData: event.MetaData{
			EndpointId: "endpointId",
		},
	}
	events = append(events, event)
	return events
}

func CreateEventsWithBinaryBody() []*event.Event {
	events := []*event.Event{}
	event := &event.Event{
		Request: &event.Request{
			URL:  "test.com/test-endpoint",
			Path: "/test-endpoint",
			Body: []byte("My binary request body"),
		},
		Response: &event.Response{
			Body: []byte("My binary response body"),
		},
		MetaData: event.MetaData{
			EndpointId: "endpointId",
		},
	}
	events = append(events, event)
	return events
}
