rule Doc_Trojan_Ocard_2
{
strings:
	$a0 = { 654d6f64756c652e41646446726f6d537472696e6720426173696c69736b }
	$a1 = { 706f6e656e74732e496d706f72742022633a5c547269626522 }
	$a2 = { 4966204d6f6e7468284e6f7729203d20313220416e6420446179284e6f7729203e3d203234205468656e }

condition:
	$a0 and $a1 and $a2
}

        