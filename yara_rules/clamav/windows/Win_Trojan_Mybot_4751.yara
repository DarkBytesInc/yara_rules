rule Win_Trojan_Mybot_4751
{
strings:
	$a0 = { e702a8954c6649dfd7bd01590b24a0ba2b6441a53b77325d6c785e97d52e5d3a7cca707efd20f45225b5a99746142667d3de45a2437d2e5fb332b449fd644966e358813ae3a329c2a5d9c04241b3ecc444011b32bee4584092528b721f9db89490f649f2d21b66c99dd3a7f8a7c85e712d83c66588d137a6482aa27166c11feffe9496f7ef8ddaca34abdb7b48388e7a13a7f3277371 }

condition:
	$a0
}

        