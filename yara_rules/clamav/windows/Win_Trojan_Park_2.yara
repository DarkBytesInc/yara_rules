rule Win_Trojan_Park_2
{
strings:
	$a0 = { cb66d934e468c1f27cc22836832c97c30fc4a5c549c597cdb259cd57c6e18dc774c8a6694e2e0ac92d466672d92c9bea6ecaf882cb2ecccb6690e515cdabcc50ced4e5b259365ecfe894d07bd1d334cdc911d2344d6ef25c36cb6576d300d48a71d507d69b65d39c28ac30d7ba44d8e672b97cf7a1d9feda }

condition:
	$a0
}

        
