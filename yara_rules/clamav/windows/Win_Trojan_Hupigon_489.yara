rule Win_Trojan_Hupigon_489
{
strings:
	$a0 = { 4e4ab641228c4b1968655b50ed32ac6575a40fb91ecb13609a9d872e5c74d7d268ac786ea2bf566da631f9bbdeb318dad396eaefb76aa21e0ccf2ddcfee680ef9d3438fdb2f45ce57dc23f669336a9389b1b22ef5e4ad5d29e4c9560433708c966a9d47c }

condition:
	$a0
}

        
