rule Doc_Trojan_Edds_1
{
strings:
	$a0 = { 496620783831333333323933203d2031205468656e20646f6d65686172646572626162793332393130203d20416374697665446f63756d656e742e46756c6c4e616d6520456c736520646f6d65686172646572626162793332393130203d204e6f726d616c54656d706c6174652e46756c6c4e616d65 }

condition:
	$a0
}

        