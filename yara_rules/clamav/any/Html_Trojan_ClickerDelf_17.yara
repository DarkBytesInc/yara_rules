rule Html_Trojan_ClickerDelf_17
{
strings:
	$a0 = { 35ec7579656975074d3f4f51c053174fbc63452dde6c787ce7ebfbb1de1449b3d8d3c567cdd3c577bdd1c5f9e8ecf8fce8604bb1bd63c5e7cdd3c5f9666a767a66f540369b2a40f950544aad6569 }

condition:
	$a0
}

        
