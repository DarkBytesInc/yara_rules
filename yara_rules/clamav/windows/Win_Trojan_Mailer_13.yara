rule Win_Trojan_Mailer_13
{
strings:
	$a0 = { 6167397a646361396967646c64676876633372696577666b7a68696f6a66397472766a7772766a62756b766e743172667830666572666a646b74736b6a686e31796d6f677073616b78316e66756c7a66756c736e736672757566396974316e756a31303769616f6b62786e6e69643067696c7875716b667472746f676a676a6863327663626e76757977316c696331686f69616b626d66747a7678757376613669637270636678757367397a64646f676a67687663337263626972776432727a786734696f776f6b7a6e6a7662736139696b7a79623230366965317072657666707369756a686e687a6d76746232726c6c69693864673976626561696c69726675307673766b76737779646976667271783068707531716e7873346970696937636d31686177776f6963726a636d7668646739796c63616b63337669616977676a67317a7a7977676a677a79623230706f77 }

condition:
	$a0
}

        