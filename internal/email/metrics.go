package email

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EmailsSentTotal tracks total number of emails sent
	EmailsSentTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "emails_sent_total",
			Help: "Total number of emails sent",
		},
		[]string{"status", "priority"},
	)

	// EmailSendDuration tracks email sending duration
	EmailSendDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "email_send_duration_seconds",
			Help:    "Email sending duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"status"},
	)

	// EmailQueueSize tracks current queue size
	EmailQueueSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "email_queue_size",
			Help: "Current number of emails in queue",
		},
	)

	// EmailRateLimitExceeded tracks rate limit violations
	EmailRateLimitExceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "email_rate_limit_exceeded_total",
			Help: "Total number of rate limit violations",
		},
		[]string{"recipient"},
	)

	// EmailRetries tracks retry attempts
	EmailRetries = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "email_retries",
			Help:    "Number of retry attempts per email",
			Buckets: []float64{0, 1, 2, 3, 4, 5, 10},
		},
		[]string{"priority"},
	)

	// EmailTemplateRenderDuration tracks template rendering duration
	EmailTemplateRenderDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "email_template_render_duration_seconds",
			Help:    "Email template rendering duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"template"},
	)

	// EmailDLQSize tracks dead letter queue size
	EmailDLQSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "email_dlq_size",
			Help: "Current number of emails in dead letter queue",
		},
	)
)
