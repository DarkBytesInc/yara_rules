rule Win_Trojan_Mytob_390
{
strings:
	$a0 = { 36b4c59988c5819e86e1ebbbaab9bf6ebbf8190676fc9baafca1a4a2a5812ddd8f5f8407e48da78fe12093c6bbbcabed3a9b8087e489e8e592984784e006527a90f1812e9d878d2ced19cba2bbd1dc829bec8a1d6dfec6dc56f8e4161d29a91186c7babea200d1a98484cadb23d4603df0888e8a988eeb8c }

condition:
	$a0
}

        
