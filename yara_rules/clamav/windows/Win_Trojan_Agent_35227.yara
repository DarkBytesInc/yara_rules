rule Win_Trojan_Agent_35227
{
strings:
	$a0 = { 68980201008d4de851ff15080501008d55f8528d45e850ff15000501008945f0837df000740f8b4df451ff15180501008b45f0eb2b8b5508c74234800401008b4508c74038600301008b4d08c74140600301008b5508c74270900301008b45f0 }

condition:
	$a0
}

        