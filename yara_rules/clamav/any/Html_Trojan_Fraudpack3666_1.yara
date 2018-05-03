rule Html_Trojan_Fraudpack3666_1
{
strings:
	$a0 = { 8d24feffff83c26829cae8f4420000b98a01000081c1ba000000198dd4feffff41398dc4feffff722ab828050000198504feffff21c803459083f8007215ff45d8298d18feffffff8528ffffffff8df4fdffff094dd8b9e6000000238d38ffffff01c101 }

condition:
	$a0
}

        
