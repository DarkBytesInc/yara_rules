rule Win_Trojan_Hupigon_1386
{
strings:
	$a0 = { c7dc9071f0c3a77488895ba30eaaf51588c739c5e9087e59127a4a07df765294ad6fb48fd7e19ee7aaa2fc2de4dfc81af4421a268e3754d82d98a1574b8b6aebe61e4b376a4af5587eadf8de55fc9ac3af8b48be42a8fe9f515e75c024bc5456cf56c7cb06a0afccb7919a265bb0ffc4a86cc5918aa9 }

condition:
	$a0
}

        
