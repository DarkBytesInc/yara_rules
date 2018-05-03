rule Win_Ircbot_Repeerc_1
{
strings:
	$a0 = { c10bf1d463554d1b1b3d3b0eece2f669ce85348d558208aa5fe40fe0edde932b7cc6af94bb6bd81b54e0e6f7f2b4abb118c1d413698d3ac54d67ffdd3cef22c9d3fce5b411f8bb8e6d5303abb41cc9961869fb701bf84c617190f0befee751d4b499df730e77bd05c9 }

condition:
	$a0
}

        
