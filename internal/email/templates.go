package email

// Email HTML templates

const emailVerificationTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #4CAF50;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Welcome to PaiGram!</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; color: #333333; font-size: 16px; line-height: 1.6;">
                                Thank you for signing up. Please verify your email address by clicking the button below:
                            </p>
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center" style="padding: 20px 0;">
                                        <a href="{{.VerifyURL}}" style="display: inline-block; padding: 14px 40px; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 4px; font-size: 16px; font-weight: bold;">Verify Email Address</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 20px 0 0; color: #666666; font-size: 14px; line-height: 1.6;">
                                Or enter this verification code: <strong>{{.Token}}</strong>
                            </p>
                            <p style="margin: 20px 0 0; color: #666666; font-size: 14px; line-height: 1.6;">
                                This link will expire in 24 hours.
                            </p>
                            <p style="margin: 20px 0 0; color: #999999; font-size: 12px; line-height: 1.6;">
                                If you did not create an account, please ignore this email.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 30px; background-color: #f8f8f8; text-align: center;">
                            <p style="margin: 0; color: #999999; font-size: 12px;">
                                © 2024 PaiGram. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`

const passwordResetTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #2196F3;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Password Reset Request</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; color: #333333; font-size: 16px; line-height: 1.6;">
                                We received a request to reset your password. Click the button below to reset it:
                            </p>
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center" style="padding: 20px 0;">
                                        <a href="{{.ResetURL}}" style="display: inline-block; padding: 14px 40px; background-color: #2196F3; color: #ffffff; text-decoration: none; border-radius: 4px; font-size: 16px; font-weight: bold;">Reset Password</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 20px 0 0; color: #666666; font-size: 14px; line-height: 1.6;">
                                This link will expire in 1 hour.
                            </p>
                            <p style="margin: 20px 0 0; color: #999999; font-size: 12px; line-height: 1.6;">
                                If you did not request a password reset, please ignore this email or contact support if you have concerns.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 30px; background-color: #f8f8f8; text-align: center;">
                            <p style="margin: 0; color: #999999; font-size: 12px;">
                                © 2024 PaiGram. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`

const passwordChangedTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #4CAF50;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Password Changed</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; color: #333333; font-size: 16px; line-height: 1.6;">
                                This email confirms that your password was successfully changed at {{.Timestamp}}.
                            </p>
                            <p style="margin: 20px 0 0; color: #666666; font-size: 14px; line-height: 1.6;">
                                If you did not make this change, please contact support immediately.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 30px; background-color: #f8f8f8; text-align: center;">
                            <p style="margin: 0; color: #999999; font-size: 12px;">
                                © 2024 PaiGram. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`

const newDeviceLoginTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Device Login</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #FF9800;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">New Device Login Alert</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; color: #333333; font-size: 16px; line-height: 1.6;">
                                A new device has logged into your account:
                            </p>
                            <table width="100%" cellpadding="8" cellspacing="0" style="margin: 20px 0;">
                                <tr>
                                    <td style="color: #666666; font-size: 14px;"><strong>Device:</strong></td>
                                    <td style="color: #333333; font-size: 14px;">{{.DeviceName}}</td>
                                </tr>
                                <tr>
                                    <td style="color: #666666; font-size: 14px;"><strong>Location:</strong></td>
                                    <td style="color: #333333; font-size: 14px;">{{.Location}}</td>
                                </tr>
                                <tr>
                                    <td style="color: #666666; font-size: 14px;"><strong>IP Address:</strong></td>
                                    <td style="color: #333333; font-size: 14px;">{{.IP}}</td>
                                </tr>
                                <tr>
                                    <td style="color: #666666; font-size: 14px;"><strong>Time:</strong></td>
                                    <td style="color: #333333; font-size: 14px;">{{.Timestamp}}</td>
                                </tr>
                            </table>
                            <p style="margin: 20px 0 0; color: #e53935; font-size: 14px; line-height: 1.6; font-weight: bold;">
                                If this was not you, please change your password immediately and contact support.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 30px; background-color: #f8f8f8; text-align: center;">
                            <p style="margin: 0; color: #999999; font-size: 12px;">
                                © 2024 PaiGram. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`

const twoFactorBackupCodesTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>2FA Backup Codes</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #9C27B0;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Your 2FA Backup Codes</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; color: #333333; font-size: 16px; line-height: 1.6;">
                                Please save these backup codes in a secure location. Each code can only be used once.
                            </p>
                            <table width="100%" cellpadding="10" cellspacing="0" style="margin: 20px 0; background-color: #f8f8f8; border-radius: 4px;">
                                <tr>
                                    <td style="font-family: 'Courier New', monospace; font-size: 14px; color: #333333;">
                                        {{range $index, $code := .BackupCodes}}
                                        {{add $index 1}}. {{$code}}<br>
                                        {{end}}
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 20px 0 0; color: #e53935; font-size: 14px; line-height: 1.6; font-weight: bold;">
                                Keep these codes safe and do not share them with anyone.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 30px; background-color: #f8f8f8; text-align: center;">
                            <p style="margin: 0; color: #999999; font-size: 12px;">
                                © 2024 PaiGram. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`
