rule Win_Spyware_5471_1
{
strings:
	$a0 = { 7366747073766300000000ffffffff050000002a2e6c6f67000000558bec33c95151515153565733c05568028c410064ff3064892033c05568dd8b410064ff306489208d45fce874d7feffba188c410033c0e8383cffff84c00f8492000000ba188c410033c0e8e03dffff84c00f848b00000033c05568ae8b410064ff306489208d45f8e836d7feff8d45 }

condition:
	$a0
}

        