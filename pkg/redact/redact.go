package redact

import (
	domainutils "github.com/supergoodsystems/supergood-go/internal/domain-utils"
	"github.com/supergoodsystems/supergood-go/pkg/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/pkg/remote-config"
)

// Redact removes the sensitive keys provided in remote config cache
// NOTE: Redact modifies events and appends redacted info to the event object
// NOTE: Redact is expecting that the endpoint Id for the event has been successfully populated
// during event creation
func Redact(events []*event.Event, rc *remoteconfig.RemoteConfig) []error {
	var errs []error
	forceRedact := rc.IsRedactAllEnabled()
	for _, e := range events {
		domain := domainutils.GetDomainFromHost(e.Request.URL)
		endpoints := rc.Get(domain)
		if len(endpoints) == 0 && !forceRedact {
			continue
		}
		endpoint := endpoints[e.MetaData.EndpointId]
		if forceRedact {
			meta, redactErrs := redactAll(domain, e, endpoint.SensitiveKeys)
			errs = append(errs, redactErrs...)
			e.MetaData.SensitiveKeys = append(e.MetaData.SensitiveKeys, meta...)
			continue
		}

		for _, sensitiveKey := range endpoint.SensitiveKeys {
			if sensitiveKey.Action != "REDACT" {
				continue
			}
			formattedParts, err := formatSensitiveKey(sensitiveKey.KeyPath)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			meta, err := redactPath(domain, e.Request.URL, sensitiveKey.KeyPath, formattedParts, e)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			e.MetaData.SensitiveKeys = append(e.MetaData.SensitiveKeys, meta...)
		}
	}
	return errs
}
