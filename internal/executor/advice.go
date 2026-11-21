package executor

// Advice is what to tell the user about a record whyreach couldn't make
// because it can't see that side from where it runs (its message is
// HostHidden, PIDsHidden or HostNotHere): the matching advice, as a
// sentence. For any other message it is "".
func Advice(msg string) string {
	switch msg {
	case HostHidden:
		return HostHiddenAdvice + "."
	case PIDsHidden:
		return PIDsHiddenAdvice + "."
	case HostNotHere:
		return HostNotHereAdvice + "."
	default:
		return ""
	}
}
