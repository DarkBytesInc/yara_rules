rule Win_Trojan_Mybot_6432
{
strings:
	$a0 = { 4db8385862b3ec616c9a6dc81640b8b5780f4e07285796896f2eadd3e8b6e81eda47f0e721c160727a196035aa055e6a77c62cee0e68375543a37bbbc8d81be12de76b403051c5d2aa7d54508f17646a165ac75d676a7d41be90e650baf3c243665f9fef8a80f96b3b3a6df6c55926d8eecfd1c23363c10558d2506c5e834dbad95f206c79e253c2698ed1b1763fb59fb208e52b5886 }

condition:
	$a0
}

        