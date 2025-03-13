package models

import "errors"

var (
	ErrUserAlreadyExists = errors.New("User already exists")
	ErrInvalidInput      = errors.New("invalid input")
	ErrUserBlocked       = errors.New("User is blocked")
	ErrInvalidID         = errors.New("invalid ID")
	ErrUserDoesNotExist  = errors.New("user does not exists")
)

const (
	MsgLoginSuccessful           = "Login successful"
	MsgLogoutSuccessful          = "Logout successful"
	MsgSignupSuccessful          = "User signed up successfully!"
	MsgEmailVerifiedSuccessfully = "Email verified successfully"
	MsgVerificationEmailResent   = "Verification email resent"
	MsgPasswordResetEmailSent    = "Password reset email sent"
	MsgPasswordResetSuccessfully = "Password reset successfully"

	MsgProfileUpdatedSuccessfully = "Profile updated successfully"
	MsgProfilePictureUploaded     = "Profile picture uploaded successfully"

	ErrRequiredFieldsEmpty = "Required fields cannot be empty"
	ErrInvalidEmailFormat  = "Invalid email format"
	ErrNegativeAge         = "Age must be positive"
	ErrPasswordComplexity  = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
	ErrPasswordLength      = "Password must be between %d and %d characters"
	ErrInvalidPhoneNumber  = "Invalid phone number format"

	MinPasswordLength = 8
	MaxPasswordLength = 72
)
