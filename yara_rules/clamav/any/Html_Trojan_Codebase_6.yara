rule Html_Trojan_Codebase_6
{
strings:
	$a0 = { 2d386436632d3962623664643230376535622220636f6465626173653d22675f6769726c3033335f30312e7478742e657865 }

condition:
	$a0
}

        