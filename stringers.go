// generated by stringer -output stringers.go -type Event,Interrupt; DO NOT EDIT

package authapi

import "fmt"

const _Event_name = "EventRegisterEventAuthEventOAuthEventAuthFailEventOAuthFailEventRecoverStartEventRecoverEndEventGetUserEventGetUserSessionEventPasswordReset"

var _Event_index = [...]uint8{13, 22, 32, 45, 59, 76, 91, 103, 122, 140}

func (i Event) String() string {
	if i < 0 || i >= Event(len(_Event_index)) {
		return fmt.Sprintf("Event(%d)", i)
	}
	hi := _Event_index[i]
	lo := uint8(0)
	if i > 0 {
		lo = _Event_index[i-1]
	}
	return _Event_name[lo:hi]
}

const _Interrupt_name = "InterruptNoneInterruptAccountLockedInterruptAccountNotConfirmedInterruptSessionExpired"

var _Interrupt_index = [...]uint8{13, 35, 63, 86}

func (i Interrupt) String() string {
	if i < 0 || i >= Interrupt(len(_Interrupt_index)) {
		return fmt.Sprintf("Interrupt(%d)", i)
	}
	hi := _Interrupt_index[i]
	lo := uint8(0)
	if i > 0 {
		lo = _Interrupt_index[i-1]
	}
	return _Interrupt_name[lo:hi]
}
