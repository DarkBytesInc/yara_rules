rule Win_Trojan_SdBot_4010
{
strings:
	$a0 = { e9c5b263169e56928337faa90ba7321e67e114444edab58bbb08a77ad1a1c2fd5dc2a94dd9ff8770cae8e723df5cac9fda26ea67877c8e62d7fb396531f7634344f6739c08dbf57e5e26e3cfc4fa692310595af3dbf58759e717 }

condition:
	$a0
}

        
