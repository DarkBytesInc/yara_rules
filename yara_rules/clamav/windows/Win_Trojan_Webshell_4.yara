rule Win_Trojan_Webshell_4
{
strings:
	$a0 = { 3c3f7068700a24617574685f7061737320202020202020203d20223633613966306561376262393830353037393662363439653835343831383435223b0a24636f6c6f722020202020202020202020203d202223646635223b0a2464656661756c745f616374696f6e2020203d202746696c65734d616e273b0a2464656661756c745f7573655f616a6178203d2074727565 }

condition:
	$a0
}

        