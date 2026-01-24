package security

// swagger:parameters changePassword
type changePasswordParams struct {
	// in: path
	// required: true
	// minimum: 1
	ID uint64 `json:"id"`
	// in: body
	// required: true
	Body changePasswordRequest
}

// swagger:parameters enable2FA confirm2FA disable2FA getDevices
type securityIDParams struct {
	// in: path
	// required: true
	// minimum: 1
	ID uint64 `json:"id"`
}

// swagger:parameters removeDevice
type removeDeviceParams struct {
	// in: path
	// required: true
	// minimum: 1
	ID uint64 `json:"id"`
	// in: path
	// required: true
	DeviceID string `json:"device_id"`
}

// swagger:parameters confirm2FA
type confirm2FAParams struct {
	// in: path
	// required: true
	// minimum: 1
	ID uint64 `json:"id"`
	// in: body
	// required: true
	Body confirm2FARequest
}

// swagger:parameters disable2FA
type disable2FAParams struct {
	// in: path
	// required: true
	// minimum: 1
	ID uint64 `json:"id"`
	// in: body
	// required: true
	Body disable2FARequest
}

// swagger:response changePasswordResponse
type changePasswordResponseWrapper struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Message string `json:"message"`
		} `json:"data"`
	}
}

// swagger:response enable2FAResponse
type enable2FAResponseWrapper struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			QRCode      string   `json:"qr_code"`
			Secret      string   `json:"secret"`
			BackupCodes []string `json:"backup_codes"`
		} `json:"data"`
	}
}

// swagger:response confirm2FAResponse
type confirm2FAResponseWrapper struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Message     string   `json:"message"`
			BackupCodes []string `json:"backup_codes"`
		} `json:"data"`
	}
}

// swagger:response disable2FAResponse
type disable2FAResponseWrapper struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Message string `json:"message"`
		} `json:"data"`
	}
}

// Device represents a login device
// swagger:model Device
type Device struct {
	// Device unique identifier
	// example: dev_abc123
	DeviceID string `json:"device_id"`
	// Device display name
	// example: Chrome 120.0 / Windows
	DeviceName string `json:"device_name"`
	// Device type
	// example: desktop
	DeviceType string `json:"device_type"`
	// Operating system
	// example: Windows
	OS string `json:"os"`
	// Browser name
	// example: Chrome
	Browser string `json:"browser"`
	// IP address
	// example: 192.168.1.100
	IP string `json:"ip"`
	// Location (City, Country)
	// example: Beijing, China
	Location string `json:"location"`
	// Last active timestamp
	// example: 2024-01-23T10:00:00Z
	LastActiveAt string `json:"last_active_at"`
	// Whether this is the current device
	// example: true
	IsCurrent bool `json:"is_current"`
	// Trust expiry date (if device is trusted)
	// example: 2024-02-23T10:00:00Z
	TrustExpiry *string `json:"trust_expiry,omitempty"`
}

// swagger:response devicesResponse
type devicesResponseWrapper struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Data []Device `json:"data"`
		} `json:"data"`
	}
}

// swagger:response removeDeviceResponse
type removeDeviceResponseWrapper struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Message string `json:"message"`
		} `json:"data"`
	}
}

// swagger:response securityErrorResponse
type securityErrorResponseWrapper struct {
	// in: body
	Body struct {
		Error struct {
			Code    string                 `json:"code"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		} `json:"error"`
	}
}
