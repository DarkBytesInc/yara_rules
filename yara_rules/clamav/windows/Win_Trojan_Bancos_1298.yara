rule Win_Trojan_Bancos_1298
{
strings:
	$a0 = { ba08d916f75a01d6d7722d501f2d601b91056e181f50ad09383b72b2065aa182ccd13321e6afe0467bb4ceb7ce0d1bc72cef2dd02c27414a896cce60d8947b242e6c707b988d213e8579d5ce4ca25ad9d1bc }

condition:
	$a0
}

        
