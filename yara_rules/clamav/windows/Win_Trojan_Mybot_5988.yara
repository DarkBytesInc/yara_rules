rule Win_Trojan_Mybot_5988
{
strings:
	$a0 = { 2b65c44aa9016b9b9fd4919efb86120e3e8ad1594c1faf5764739c3286023648bc7becdef52e296473dc3e92cb7d35173f1306ccfe23cf5d029ef1be6c3741a599387b543ceb92eca76f1f1fc5bf95724a9d }

condition:
	$a0
}

        
