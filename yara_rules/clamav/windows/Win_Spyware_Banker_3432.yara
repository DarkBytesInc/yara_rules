rule Win_Spyware_Banker_3432
{
strings:
	$a0 = { 7fcc70c2e7dc710f71ce31cba0d77477f9d323be1c19ad175c0f7c6d599c33bc1ac0bf8ff9d9b1f160c5609ffab158b94cfc1dbe0fc4c7f0fed73c4e842fa0a9a75a0de68dbf2d70e95064418cb3feb12b674831d0b57ccf508b46d3357020 }

condition:
	$a0
}

        
