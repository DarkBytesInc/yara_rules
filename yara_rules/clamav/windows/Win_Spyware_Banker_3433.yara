rule Win_Spyware_Banker_3433
{
strings:
	$a0 = { 8e2f120ce304866cbbc27e84aad8e61f451ab62062053ed9cf8bbedc363b73d39b93e60faf02101bb5dac5afcb2d568910b358c7eb88c5dbcd690f4002408574ae718b774d1e090aa169d5cd463c70898e75270d3af8ff78f172a723cd255c }

condition:
	$a0
}

        
