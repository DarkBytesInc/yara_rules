rule Win_Spyware_180_2
{
strings:
	$a0 = { 76688d9554ffffff33c0e81ff7ffff8b8554ffffffba14554000e8cfe4ffff8d9550ffffff33c0e802f7ffff8b8550ffffffba14554000e8b2e4ffff68cc554000a1b06040008b0050e860ebffff8bd8a1bc6040008918a1bc60400085db740a8b1dbc6040008b1bffd3 }

condition:
	$a0
}

        
