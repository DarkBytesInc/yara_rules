rule Win_Downloader_Agent_32787
{
strings:
	$a0 = { 3ec8d300d480c564d941e2d93c440f0c39c30fa90ac32a53e03aa5054647dc9dc1521ea0d39208e513586535c416d1ceee225d71d66b20de5a1f97ed1c54c0172dcfe07c42a8c89715327e }

condition:
	$a0
}

        
