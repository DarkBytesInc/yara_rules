rule Win_Trojan_Renos_28
{
strings:
	$a0 = { 2195a0feffff31c283ea2e83fa4875033145d8ff85c0fdffff098520ffffffb8a800000081c09600000081e8001c000021c821856cfeffffff85c0feffff01856cfdffff81f8220f00007630b989060000ff856cffffff118dd8feffffff85a4feffff01 }

condition:
	$a0
}

        
