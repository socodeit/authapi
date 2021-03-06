// Package lock implements user locking after N bad sign-in attempts.
package lock

import (
	"errors"
	"time"

	"github.com/socodeit/authapi"
)

// Storage key constants
const (
	StoreAttemptNumber = "attempt_number"
	StoreAttemptTime   = "attempt_time"
	StoreLocked        = "locked"
)

var (
	errUserMissing = errors.New("lock: user not loaded in BeforeAuth callback")
)

func init() {
	authapi.RegisterModule("lock", &Lock{})
}

// Lock module
type Lock struct {
	*authapi.Authapi
}

// Initialize the module
func (l *Lock) Initialize(ab *authapi.Authapi) error {
	l.Authapi = ab
	if l.Storer == nil && l.StoreMaker == nil {
		return errors.New("lock: Need a Storer")
	}

	// Events
	l.Callbacks.After(authapi.EventGetUser, func(ctx *authapi.Context) error {
		_, err := l.beforeAuth(ctx)
		return err
	})
	l.Callbacks.Before(authapi.EventAuth, l.beforeAuth)
	l.Callbacks.After(authapi.EventAuth, l.afterAuth)
	l.Callbacks.After(authapi.EventAuthFail, l.afterAuthFail)

	return nil
}

// Routes for the module
func (l *Lock) Routes() authapi.RouteTable {
	return nil
}

// Storage requirements
func (l *Lock) Storage() authapi.StorageOptions {
	return authapi.StorageOptions{
		l.PrimaryID:        authapi.String,
		StoreAttemptNumber: authapi.Integer,
		StoreAttemptTime:   authapi.DateTime,
		StoreLocked:        authapi.DateTime,
	}
}

// beforeAuth ensures the account is not locked.
func (l *Lock) beforeAuth(ctx *authapi.Context) (authapi.Interrupt, error) {
	if ctx.User == nil {
		return authapi.InterruptNone, errUserMissing
	}

	if locked, ok := ctx.User.DateTime(StoreLocked); ok && locked.After(time.Now().UTC()) {
		return authapi.InterruptAccountLocked, nil
	}

	return authapi.InterruptNone, nil
}

// afterAuth resets the attempt number field.
func (l *Lock) afterAuth(ctx *authapi.Context) error {
	if ctx.User == nil {
		return errUserMissing
	}

	ctx.User[StoreAttemptNumber] = int64(0)
	ctx.User[StoreAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(); err != nil {
		return err
	}

	return nil
}

// afterAuthFail adjusts the attempt number and time.
func (l *Lock) afterAuthFail(ctx *authapi.Context) error {
	if ctx.User == nil {
		return errUserMissing
	}

	lastAttempt := time.Now().UTC()
	if attemptTime, ok := ctx.User.DateTime(StoreAttemptTime); ok {
		lastAttempt = attemptTime
	}

	var nAttempts int64
	if attempts, ok := ctx.User.Int64(StoreAttemptNumber); ok {
		nAttempts = attempts
	}

	nAttempts++

	if time.Now().UTC().Sub(lastAttempt) <= l.LockWindow {
		if nAttempts >= int64(l.LockAfter) {
			ctx.User[StoreLocked] = time.Now().UTC().Add(l.LockDuration)
		}

		ctx.User[StoreAttemptNumber] = nAttempts
	} else {
		ctx.User[StoreAttemptNumber] = int64(1)
	}
	ctx.User[StoreAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(); err != nil {
		return err
	}

	return nil
}

// Lock a user manually.
func (l *Lock) Lock(key string) error {
	user, err := l.Storer.Get(key)
	if err != nil {
		return err
	}

	attr := authapi.Unbind(user)
	if err != nil {
		return err
	}

	attr[StoreLocked] = time.Now().UTC().Add(l.LockDuration)

	return l.Storer.Put(key, attr)
}

// Unlock a user that was locked by this module.
func (l *Lock) Unlock(key string) error {
	user, err := l.Storer.Get(key)
	if err != nil {
		return err
	}

	attr := authapi.Unbind(user)
	if err != nil {
		return err
	}

	// Set the last attempt to be -window*2 to avoid immediately
	// giving another login failure.
	attr[StoreAttemptTime] = time.Now().UTC().Add(-l.LockWindow * 2)
	attr[StoreAttemptNumber] = int64(0)
	attr[StoreLocked] = time.Now().UTC().Add(-l.LockDuration)

	return l.Storer.Put(key, attr)
}
