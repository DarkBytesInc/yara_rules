rule Win_Downloader_Swizzor_507
{
strings:
	$a0 = { 5e4b65b3bf4f3afe1f2fd1cd2ffa9c15cb97ce59df97caf1233778a8ef07417c7e7ecfc8f7f66e6969458323a6bc26a985ef2ef892243af3bdedad92b5e23eb6568b8c0bfd9e29a777723b448cc85b74108d8db5621e86db5b51a45d53c7b62c69b3ce7f776293baa0 }

condition:
	$a0
}

        
