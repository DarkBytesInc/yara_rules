rule Win_Dropper_Delf_716
{
strings:
	$a0 = { ced6eee8ebe2797979efe5d5eded797979e4d1d6ededd8e5ebdae2e0efd5797979c68c6dfab5c9787878c7c08c36718c698efe51a2777979796496d37978c651f2367d8c3661c978c66dd7f23657b0f6c9787878857979798ef6c9787878c978c6698cf6d9787878f4517be62df4bec578787876e614f4bec17878787aeb0dd78c365774b9d7f236576c0fd78c365774b9d7f4b97bd7 }

condition:
	$a0
}

        