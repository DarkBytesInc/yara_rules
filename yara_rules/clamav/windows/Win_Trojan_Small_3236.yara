rule Win_Trojan_Small_3236
{
strings:
	$a0 = { bd49f7973a05d37fe9b074f01345d30a0379f0bff68d17a452a54f9d36055ccc1a655bc41a6d8cbdf604d3b2b6924fa45f8e27a45af87e0d4229d70c4a29ebd0486b7eeaf66ed3e93a6fd329600560c41a7d }

condition:
	$a0
}

        
