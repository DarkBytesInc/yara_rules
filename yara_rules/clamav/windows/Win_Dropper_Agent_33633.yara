rule Win_Dropper_Agent_33633
{
strings:
	$a0 = { 710cb4f5464905c56fb34f84e8d37e3c46a751fa2be5b13babd02d24e05d1ef8367ce8f9ea98c0bea4b94aaae9ec01ae3ebaefc6680d581ec7fae201f78eed35b277405b6b66e3d622dbd47b30dcbc2e2b68e661 }

condition:
	$a0
}

        
