rule Win_Trojan_DNSchanger_1
{
strings:
	$a0 = { e3681389e389c0b589e31cf6bbf3a3e3662397d168ded3f3a3e3b51c34662397c6b51c34639fd31cbf96ebb51c346387d31ce38ba3f5a3e3b51cf6cff3a3e3b50be7e3e3e3babcbd20b0b658e3f3e3e3b5b089eb1cf6dbf3a3e3b31cf6dff3a3e3688fc7f36813b6b0b51cf6c3f3a3e363dde397b5b468de }

condition:
	$a0
}

        
