rule Win_Trojan_Mybot_8495
{
strings:
	$a0 = { afc609ea7332e2584290978fcce8b463d97eba896b46f086123faae11c5dc5580fd464945babbee9593c0fb98146afcc713e6022ef302c2298d7e3062d3dfd86aed278e29abe8808c130f72c6ad07e1e3dfece136d }

condition:
	$a0
}

        
