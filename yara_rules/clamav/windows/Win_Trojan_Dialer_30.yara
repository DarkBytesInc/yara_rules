rule Win_Trojan_Dialer_30
{
strings:
	$a0 = { 55434b3f34ea0acd000d5c494558502bc0a8fb4c4f52452e0fce96f63a2a389f41498ea3ee680f4f7385002a4e5aef7fc24c67524f4e494320470d554fef01de1e6963bf646e016a9161e180fb0f11706661626a690b51f0c3d3d3399d6b3166f16b616add450bc4af2c542d733f8ddd }

condition:
	$a0
}

        