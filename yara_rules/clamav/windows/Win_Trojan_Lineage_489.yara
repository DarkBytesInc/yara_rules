rule Win_Trojan_Lineage_489
{
strings:
	$a0 = { a5b2eecdd3bf25d3bcc47245ef9f89622e0bbb635701ca9a09c5715476cea49a74054635d73241952dcb4672eb789dfbd5214b2d480ce7438adc8b1c41fa71b7827e9b1c8c9a814bfd7211b3de60ca2e95d353bac0838ba2a2e9d74b1e89df7393778e9e }

condition:
	$a0
}

        
