rule Win_Trojan_SdBot_3828
{
strings:
	$a0 = { 723f9a44ae584375cbffc5fe9b5f75d57a6c6543368ddac791274e98acbcdebe71e5c7a849ee39f819d5d754b82146f1dcc5446fd6fc357d74e8d824262cafa4b69f761b2cad4f1720f1387eadd1d47d1cdca329af0b23d27e8bfd1be64dae8bb34f }

condition:
	$a0
}

        
