rule Win_Trojan_Tonerok_1
{
strings:
	$a0 = { fbffffe84e0e0000ffb5b4fbffffe84f0e00008bc88bbdb4fbffff03c78bf8803f5c751347578d85bcfbffff50e8240e0000c60700eb034fe2e5ffb5b4fbffff8d85bcfdffff50e80a0e0000ffb5b4fbffff8d85bcfcffff50e8f80d0000688c }

condition:
	$a0
}

        
