rule Win_Spyware_Banker_2020
{
strings:
	$a0 = { 98e3b844e28c4b8fb89adaa121c15fcfbe0285617f37bb526ae1dff4c86cc4e7fcef80ca6586f7f899a50ab60b0647667d0ee8eb8bd7cff980b34251d99d188c3026ae2e2d5d733da77e9d187520b267c7bb4b101a8bbecb7e9c0ce4a97ac87c1db93d513bb67d48d25ed792e84445593b5f }

condition:
	$a0
}

        
