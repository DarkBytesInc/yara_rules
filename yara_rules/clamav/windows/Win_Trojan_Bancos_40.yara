rule Win_Trojan_Bancos_40
{
strings:
	$a0 = { 7665092577696e737973255c0a003e3c457865632e6578650000000000000000504b030414000000080000b08529be5957d7c0d70000c0aa01000c0000004d5357494e53434b2e4f4358ecfd0b7c5355d6308c9fb4691b2090145a5aa46a2c45ab14ad16b03554036d4291b6a404123a42a1d2d6104b5bdb7300c7b6b4930609872833 }

condition:
	$a0
}

        