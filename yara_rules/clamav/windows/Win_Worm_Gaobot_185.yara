rule Win_Worm_Gaobot_185
{
strings:
	$a0 = { 70548850415452084efe43554b10ffc8564d530e472025736e3a6163726577dc796f61751d210d0ac14b4c24471c6f2068ce6d65ac6e3c626d212154bc08523c9c00546f70696343036d642e4e6574576110500c207d2dc8096e9073397c70dc771c335c321976112d91092b054d4f44450a2c6d1c0a }

condition:
	$a0
}

        