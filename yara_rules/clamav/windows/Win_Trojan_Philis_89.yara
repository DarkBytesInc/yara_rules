rule Win_Trojan_Philis_89
{
strings:
	$a0 = { 15c5f3713ee09516194dd113a78d35dddf282c871eb2b457a07c617946665b0f906113552d8804d02f121378fc8ad8aa3ae7b63f44f53f3ee46fd85cf86e3c5ec595ea48e56d5169a9dfbb6eae876f60e8ab99db3c999d8ae84a4138a0b633046d39d3b0bda94030985814e5686b1e3b79ff65218c6b7d1dcf26decece4eadb8341220940cc6a1f8af4f706ba14ac0ae6283d30539 }

condition:
	$a0
}

        