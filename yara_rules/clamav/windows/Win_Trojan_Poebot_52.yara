rule Win_Trojan_Poebot_52
{
strings:
	$a0 = { c702c1eb5083e800000000eb32b8b9e3d00000eb3c810f8503000000eb05a1aceb21b8e9a7b40000ebffb88bfeebdf8ad2c8eb2ab832c1ebc800f6d0ebf7835eeb06c734a0ebf32581c6e8b30000ebdbe8fcebcb8bfec8ebd7e949ebb98baaebf9 }

condition:
	$a0
}

        
