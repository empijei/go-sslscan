// Code generated by "stringer -type ProtVersion"; DO NOT EDIT.

package scanner

import "strconv"

const _ProtVersion_name = "SSL30TLS10TLS11TLS12"

var _ProtVersion_index = [...]uint8{0, 5, 10, 15, 20}

func (i ProtVersion) String() string {
	i -= 768
	if i >= ProtVersion(len(_ProtVersion_index)-1) {
		return "ProtVersion(" + strconv.FormatInt(int64(i+768), 10) + ")"
	}
	return _ProtVersion_name[_ProtVersion_index[i]:_ProtVersion_index[i+1]]
}
