rule Win_Trojan_SdBot_3807
{
strings:
	$a0 = { f9ae60f6f5f4f368fed9d236edec6faffe766d8fdde4e333ca33a1dddd36672006c2783bd6d55f5816d0cfcecd81512bc9c8c72f565207c3aaff97bfbe1615407a2dd5423bf9b3b2b1b064340eacabaa124535eaa68dc57aa2a1f9f8235d1102251e }

condition:
	$a0
}

        
