rule Win_Trojan_SdBot_3913
{
strings:
	$a0 = { c4311ec8f7fa4cc14e99a20aae2ad9ac163d12f5b62caa04e930cd6d70f1600ad29180e6cba07702414ed83328b4a73574cc38d524e69d1b4f19782117def076f9fbc6b9629ee57f8a68a97fc3d5cad4da86b8f9f0d6c8d671ef8f23 }

condition:
	$a0
}

        
