rule Win_Trojan_LdPinch_101
{
strings:
	$a0 = { 5ee94bcb5256414472ce4817419a165b55e81d89a9161c384252882859868a7968a2dea12e1a65971b1ce321ac8a4e84631632b93948fe1c5df494501422a8a46899d09decdfdc176449e9597962ac17185fc72145f4da298796b3527a2c0a2b6877a0599715d472ad7f7d25f4fe664662462beb }

condition:
	$a0
}

        