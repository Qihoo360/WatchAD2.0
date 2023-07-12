package event_decoder

import (
	"time"
)

type SystemEvent struct {
	TimeStamp time.Time              `json:"@timestamp"`
	Tags      []string               `json:"tags"`
	WinLog    WinLog                 `json:"winlog"`
	Agent     map[string]interface{} `json:"agent"`
}

type WinLog struct {
	EventID      int                    `json:"event_id"`
	ComputerName string                 `json:"computer_name"`
	EventData    map[string]interface{} `json:"event_data"`
	ProviderName string                 `json:"provider_name"`
}
