rule Win_Trojan_SdBot_4044
{
strings:
	$a0 = { cc53e3c0340ad43a7955ded8a9fd9b88d3466f10bb8b32fe05e8fc794c77b4a9233643c8832a0ba1001a61437a7d549badbeb9dfbc1d50b5909cbe09fdda2dd537e0aa4635ccf5413865fd4740c4a886e64fb17ca630 }

condition:
	$a0
}

        
